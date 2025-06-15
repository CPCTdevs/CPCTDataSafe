// Configuração da API
const API_ENDPOINT = "https://api.cpctdatasafe.com.br";
const API_ENDPOINT_HTTP_FALLBACK = "http://api.cpctdatasafe.com.br"; // Fallback HTTP para testes
const API_KEY = "abcd123";

// Auth endpoints
const AUTH_ENDPOINTS = {
  LOGIN: `${API_ENDPOINT}/api/v1/auth/login`,
  REGISTER: `${API_ENDPOINT}/api/v1/auth/register`,
  // Fallback endpoints
  LOGIN_HTTP: `${API_ENDPOINT_HTTP_FALLBACK}/api/v1/auth/login`,
  REGISTER_HTTP: `${API_ENDPOINT_HTTP_FALLBACK}/api/v1/auth/register`
};

// Função para formatar timestamp compatível com o servidor
function getCompatibleTimestamp() {
  const now = new Date();
  // Formato sem milissegundos e com +00:00 ao invés de Z
  return now.toISOString().slice(0, 19) + '+00:00';
}

// Exportar as constantes
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    API_ENDPOINT,
    API_ENDPOINT_HTTP_FALLBACK,
    API_KEY,
    AUTH_ENDPOINTS,
    getCompatibleTimestamp
  };
}

if (typeof globalThis !== 'undefined') {
   globalThis.API_ENDPOINT = API_ENDPOINT;
   globalThis.API_ENDPOINT_HTTP_FALLBACK = API_ENDPOINT_HTTP_FALLBACK;
   globalThis.API_KEY = API_KEY;
   globalThis.AUTH_ENDPOINTS = AUTH_ENDPOINTS;
 }
