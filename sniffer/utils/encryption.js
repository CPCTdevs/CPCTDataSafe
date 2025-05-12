// Encryption utilities for CPCT Data Safe
const ENCRYPTION_CHUNK_SIZE = 190; // RSA-2048 can encrypt 190 bytes at a time

class Encryption {
  static async loadPublicKey() {
    try {
      console.log('[CPCT Encryption] Tentando carregar chave pública...');
      const keyUrl = chrome.runtime.getURL('keys/rsa_public.pem');
      console.log('[CPCT Encryption] URL da chave:', keyUrl);
      
      const response = await fetch(keyUrl);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const publicKeyPEM = await response.text();
      if (!publicKeyPEM.includes('-----BEGIN PUBLIC KEY-----')) {
        throw new Error('Invalid public key format');
      }
      
      console.log('[CPCT Encryption] Chave pública carregada com sucesso');
      return publicKeyPEM;
    } catch (error) {
      console.error('[CPCT Encryption] Erro ao carregar chave pública:', error);
      throw new Error(`Failed to load public key: ${error.message}`);
    }
  }

  static async encryptData(data) {
    try {
      console.log('[CPCT Encryption] Iniciando processo de criptografia...');
      const publicKey = await this.loadPublicKey();
      const key = await this.importPublicKey(publicKey);
      
      if (!data) {
        throw new Error('No data provided for encryption');
      }
      
      const dataStr = JSON.stringify(data);
      console.log('[CPCT Encryption] Dados convertidos para string, tamanho:', dataStr.length);
      
      const encoder = new TextEncoder();
      const fullBuf = encoder.encode(dataStr).buffer;
      console.log('[CPCT Encryption] Dados convertidos para ArrayBuffer, tamanho:', fullBuf.byteLength);
      
      const rawChunks = this.chunkArrayBuffer(fullBuf, ENCRYPTION_CHUNK_SIZE);
      console.log('[CPCT Encryption] Dados divididos em', rawChunks.length, 'chunks de bytes');
      
      const encryptedChunks = [];
      for (let i = 0; i < rawChunks.length; i++) {
        try {
          console.log(`[CPCT Encryption] Processando chunk ${i + 1}/${rawChunks.length}, tamanho: ${rawChunks[i].byteLength} bytes`);
          
          const encrypted = await self.crypto.subtle.encrypt(
            {
              name: "RSA-OAEP"
            },
            key,
            rawChunks[i]
          );
          
          const encryptedBase64 = this.arrayBufferToBase64(encrypted);
          console.log(`[CPCT Encryption] Chunk ${i + 1} criptografado com sucesso, tamanho base64: ${encryptedBase64.length}`);
          
          encryptedChunks.push(encryptedBase64);
        } catch (chunkError) {
          console.error(`[CPCT Encryption] Erro detalhado ao criptografar chunk ${i + 1}:`, {
            error: chunkError,
            chunkSize: rawChunks[i].byteLength,
            stack: chunkError.stack
          });
          throw new Error(`Failed to encrypt chunk ${i + 1}: ${chunkError.message}`);
        }
      }

      console.log('[CPCT Encryption] Todos os chunks foram criptografados com sucesso');
      return {
        encrypted: true,
        chunks: encryptedChunks,
        originalLength: fullBuf.byteLength
      };
    } catch (error) {
      console.error('[CPCT Encryption] Erro durante o processo de criptografia:', error);
      throw new Error(`Failed to encrypt data: ${error.message}`);
    }
  }

  static async importPublicKey(pemKey) {
    try {
      console.log('[CPCT Encryption] Iniciando importação da chave pública...');
      const pemHeader = '-----BEGIN PUBLIC KEY-----';
      const pemFooter = '-----END PUBLIC KEY-----';
      
      if (!pemKey.includes(pemHeader) || !pemKey.includes(pemFooter)) {
        throw new Error('Invalid PEM format');
      }
      
      // Extrair o conteúdo base64 da chave PEM
      const pemContents = pemKey
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '')
        .trim();
      
      console.log('[CPCT Encryption] Conteúdo PEM extraído, tamanho:', pemContents.length);
      
      // Verificar se o conteúdo é válido base64
      if (!/^[A-Za-z0-9+/=]+$/.test(pemContents)) {
        throw new Error('Invalid base64 content in PEM');
      }
      
      const binaryDer = this.base64ToArrayBuffer(pemContents);
      console.log('[CPCT Encryption] Chave convertida para formato binário, tamanho:', binaryDer.byteLength);

      const key = await self.crypto.subtle.importKey(
        'spki',
        binaryDer,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        false,
        ['encrypt']
      );
      
      console.log('[CPCT Encryption] Chave importada com sucesso');
      return key;
    } catch (error) {
      console.error('[CPCT Encryption] Erro ao importar chave pública:', error);
      throw new Error(`Failed to import public key: ${error.message}`);
    }
  }

  static base64ToArrayBuffer(base64) {
    try {
      // Garantir que a string base64 está corretamente formatada
      const cleanBase64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
      
      // Verificar se o comprimento é válido para base64
      if (cleanBase64.length % 4 !== 0) {
        throw new Error('Invalid base64 string length');
      }
      
      const binaryString = atob(cleanBase64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error('[CPCT Encryption] Erro ao converter base64 para ArrayBuffer:', error);
      throw new Error(`Failed to convert base64: ${error.message}`);
    }
  }

  static arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  }

  static chunkArrayBuffer(buffer, chunkSize) {
    const bytes = new Uint8Array(buffer);
    const chunks = [];
    for (let i = 0; i < bytes.length; i += chunkSize) {
      chunks.push(bytes.slice(i, i + chunkSize).buffer);
    }
    return chunks;
  }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Encryption };
} 