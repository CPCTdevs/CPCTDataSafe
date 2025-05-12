from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import json
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class Decryption:
    def __init__(self):
        self.private_key = None
        self.load_private_key()

    def load_private_key(self):
        try:
            key_path = Path(__file__).parent.parent / 'keys' / 'rsa_private.pem'
            with open(key_path, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        except Exception as e:
            raise Exception(f"Failed to load private key: {str(e)}")

    def decrypt_chunk(self, encrypted_chunk):
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_chunk)
            
            # Decrypt using private key
            decrypted = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Erro ao descriptografar chunk: {str(e)}")
            raise Exception(f"Failed to decrypt chunk: {str(e)}")

    def decrypt_data(self, encrypted_data):
        try:
            # Se não for um dicionário, retorna os dados como estão
            if not isinstance(encrypted_data, dict):
                return encrypted_data

            # Se não tiver chunks, retorna os dados como estão
            if 'chunks' not in encrypted_data:
                return encrypted_data

            # Decrypt each chunk
            decrypted_chunks = []
            for chunk in encrypted_data['chunks']:
                try:
                    decrypted_chunk = self.decrypt_chunk(chunk)
                    decrypted_chunks.append(decrypted_chunk)
                except Exception as chunk_error:
                    logger.error(f"Erro ao descriptografar chunk específico: {str(chunk_error)}")
                    raise

            # Combine chunks
            decrypted_str = ''.join(decrypted_chunks)

            # Parse JSON
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError as json_error:
                logger.error(f"Erro ao decodificar JSON descriptografado: {str(json_error)}")
                raise Exception(f"Failed to parse decrypted JSON: {str(json_error)}")

        except Exception as e:
            logger.error(f"Erro ao descriptografar dados: {str(e)}")
            raise Exception(f"Failed to decrypt data: {str(e)}") 