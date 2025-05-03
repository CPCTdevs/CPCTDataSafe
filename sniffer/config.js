// Configuração da API
const API_ENDPOINT = "http://localhost:5000/data";
const API_KEY = "12345abcde";

// Exportar as constantes
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    API_ENDPOINT,
    API_KEY
  };
}
