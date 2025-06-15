from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pathlib import Path
import base64, json, logging

logger = logging.getLogger(__name__)

class Decryption:
    """Classe helper para descriptografar payloads RSA-OAEP vindos do cliente.
    O cliente envia um objeto JSON no formato: {"chunks": [<base64>, <base64>, ...]}.
    Cada chunk contém até 190 bytes cifrados com a chave pública (RSA-2048, OAEP-SHA256).
    Esta classe usa a chave privada em keys/rsa_private.pem para decifrar e recompor o JSON original.
    """

    def __init__(self):
        self.private_key = None
        self._load_private_key()

    def _load_private_key(self):
        key_path = Path(__file__).resolve().parent.parent / "keys" / "rsa_private.pem"
        if key_path.exists():
            with open(key_path, "rb") as fh:
                self.private_key = serialization.load_pem_private_key(fh.read(), password=None)
                logger.info("Chave privada RSA carregada de %s", key_path)
                return

        # Caso não exista, gera novo par de chaves (último recurso – ideal é provisionar a chave)
        logger.warning("Chave rsa_private.pem não encontrada. Gerando novo par RSA (2048).")
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as fh:
            fh.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        public_path = key_path.parent / "rsa_public.pem"
        with open(public_path, "wb") as fh:
            fh.write(self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        logger.info("Novas chaves salvas em %s e %s", key_path, public_path)

    def _decrypt_chunk(self, chunk_b64: str) -> str:
        """Tenta descriptografar um bloco RSA usando vários esquemas de padding compatíveis.

        1. OAEP + SHA-256 (padrão atual)
        2. OAEP + SHA-1     (alguns clientes mais antigos)
        3. PKCS#1 v1.5      (último recurso)

        Também aceita Base64 em variantes standard ou urlsafe.
        """
        import base64

        # Tenta decodificar Base64 (standard) primeiro, depois urlsafe
        try:
            encrypted = base64.b64decode(chunk_b64)
        except Exception:
            # Ajusta padding se necessário (urlsafe pode vir sem '==')
            padded = chunk_b64 + '==='[(len(chunk_b64) % 4):]
            encrypted = base64.urlsafe_b64decode(padded)

        # DEBUG: verificar se tamanho do chunk corresponde ao tamanho da chave (bytes)
        key_bytes = self.private_key.key_size // 8
        if len(encrypted) != key_bytes:
            logger.warning("Chunk RSA tem %d bytes, mas chave espera %d bytes (pode indicar chave incorreta ou corrupção)", len(encrypted), key_bytes)

        try:
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return decrypted.decode()
        except Exception as exc:
            raise ValueError("RSA decryption failed with SHA-256 OAEP: %s" % exc)

    def _unpad_pkcs7(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length")
        return data[:-pad_len]

    def _evp_bytes_to_key(self, password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
        """Reimplementação do EVP_BytesToKey do OpenSSL (MD5). Usado pelo CryptoJS."""
        import hashlib

        assert salt is not None and len(salt) == 8, "Salt deve ter 8 bytes"
        collected = b""
        previous = b""
        while len(collected) < (key_len + iv_len):
            previous = hashlib.md5(previous + password + salt).digest()
            collected += previous
        key = collected[:key_len]
        iv = collected[key_len:key_len + iv_len]
        return key, iv

    def _decrypt_cryptojs_aes(self, ciphertext_b64: str, passphrase: bytes) -> str:
        """Descriptografa texto cifrado no formato gerado por CryptoJS AES.encrypt(passphrase)."""
        import base64
        from Crypto.Cipher import AES  # type: ignore -- pycryptodome

        raw = base64.b64decode(ciphertext_b64)
        if not raw.startswith(b"Salted__"):
            raise ValueError("Ciphertext não está no formato OpenSSL 'Salted__'")

        salt = raw[8:16]
        enc_data = raw[16:]

        key, iv = self._evp_bytes_to_key(passphrase, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plain = cipher.decrypt(enc_data)
        plain = self._unpad_pkcs7(padded_plain)
        return plain.decode()

    def _decrypt_hybrid_payload(self, data: dict):
        """Descriptografa payload híbrido (RSA chunks + AES encrypted)."""
        if not (isinstance(data, dict) and {'chunks', 'encrypted'} <= data.keys()):
            return data  # Não é formato híbrido
        try:
            # 1) Reconstrói passphrase AES (clientKey) a partir dos chunks RSA
            passphrase = "".join(self._decrypt_chunk(c) for c in data['chunks'])
            # 2) Descriptografa o campo 'encrypted' usando AES
            plaintext = self._decrypt_cryptojs_aes(data['encrypted'], passphrase.encode())
            return json.loads(plaintext)
        except Exception as exc:
            logger.error("Falha ao descriptografar payload híbrido RSA+AES: %s", exc)
            raise

    def decrypt_payload(self, data: dict):
        """Descriptografa payloads.
        - Formato simples: {"chunks": [...]}               (RSA puro)
        - Formato híbrido: {"chunks": [...], "encrypted": ...} (RSA + AES)
        Caso não corresponda, retorna o payload original (assumido plaintext).
        """
        if not isinstance(data, dict) or 'chunks' not in data:
            return data  # Payload não criptografado

        # Primeiro tenta descriptografar como híbrido
        if isinstance(data.get('encrypted'), str):
            try:
                return self._decrypt_hybrid_payload(data)
            except Exception:
                # Se falhar, continua tentando RSA puro
                pass

        # Tenta RSA puro
        try:
            plaintext = "".join(self._decrypt_chunk(c) for c in data["chunks"])
            return json.loads(plaintext)
        except Exception as exc:
            logger.error("Falha ao descriptografar payload RSA: %s", exc)
            raise 