// Gerenciador de usuários para a extensão CPCT Data Safe

/**
 * Classe para gerenciar usuários e autenticação
 */
class UserManager {
  constructor() {
    this.currentUser = null;
    this.isInitialized = false;
  }

  /**
   * Inicializa o gerenciador de usuários
   * @returns {Promise} Promise que resolve quando a inicialização estiver completa
   */
  async initialize() {
    if (this.isInitialized) return;
    
    try {
      const result = await this.getStorageData(['userLoggedIn', 'userId', 'username', 'lastLogin']);
      
      if (result.userLoggedIn && result.userId) {
        this.currentUser = {
          userId: result.userId,
          username: result.username,
          lastLogin: result.lastLogin
        };
        console.log('UserManager: Usuário já logado:', this.currentUser.username);
      } else {
        console.log('UserManager: Nenhum usuário logado');
      }
      
      this.isInitialized = true;
    } catch (error) {
      console.error('UserManager: Erro ao inicializar:', error);
    }
  }

  /**
   * Obtém dados do armazenamento local
   * @param {Array} keys Chaves a serem obtidas
   * @returns {Promise} Promise que resolve com os dados
   */
  getStorageData(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (result) => {
        resolve(result);
      });
    });
  }

  /**
   * Define dados no armazenamento local
   * @param {Object} data Dados a serem armazenados
   * @returns {Promise} Promise que resolve quando os dados forem armazenados
   */
  setStorageData(data) {
    return new Promise((resolve) => {
      chrome.storage.local.set(data, () => {
        resolve();
      });
    });
  }

  /**
   * Verifica se um usuário está logado
   * @returns {Boolean} Verdadeiro se um usuário estiver logado
   */
  isUserLoggedIn() {
    return this.currentUser !== null;
  }

  /**
   * Obtém o ID do usuário atual
   * @returns {String|null} ID do usuário ou null se nenhum usuário estiver logado
   */
  getCurrentUserId() {
    return this.currentUser ? this.currentUser.userId : null;
  }

  /**
   * Obtém o nome de usuário atual
   * @returns {String|null} Nome de usuário ou null se nenhum usuário estiver logado
   */
  getCurrentUsername() {
    return this.currentUser ? this.currentUser.username : null;
  }

  /**
   * Obtém informações completas do usuário atual
   * @returns {Object|null} Objeto com informações do usuário ou null se nenhum usuário estiver logado
   */
  getCurrentUser() {
    return this.currentUser;
  }

  /**
   * Registra um novo usuário
   * @param {String} username Nome de usuário
   * @param {String} password Senha
   * @returns {Promise} Promise que resolve com o resultado do registro
   */
  async registerUser(username, password) {
    try {
      // Verificar se o usuário já existe
      const result = await this.getStorageData(['users']);
      const users = result.users || {};
      
      if (users[username]) {
        return { success: false, message: 'Este nome de usuário já está em uso' };
      }
      
      // Gerar ID único para o usuário
      const userId = this.generateUniqueId();
      
      // Adicionar novo usuário
      users[username] = {
        userId: userId,
        password: this.hashPassword(password),
        createdAt: new Date().toISOString()
      };
      
      // Salvar usuários atualizados
      await this.setStorageData({ users: users });
      
      return { success: true, userId: userId };
    } catch (error) {
      console.error('UserManager: Erro ao registrar usuário:', error);
      return { success: false, message: 'Erro ao registrar usuário' };
    }
  }

  /**
   * Autentica um usuário
   * @param {String} username Nome de usuário
   * @param {String} password Senha
   * @returns {Promise} Promise que resolve com o resultado da autenticação
   */
  async loginUser(username, password) {
    try {
      // Verificar credenciais
      const result = await this.getStorageData(['users']);
      const users = result.users || {};
      
      if (users[username] && users[username].password === this.hashPassword(password)) {
        const userId = users[username].userId;
        
        // Armazenar informações de login
        await this.setStorageData({
          userLoggedIn: true,
          userId: userId,
          username: username,
          lastLogin: new Date().toISOString()
        });
        
        // Atualizar usuário atual
        this.currentUser = {
          userId: userId,
          username: username,
          lastLogin: new Date().toISOString()
        };
        
        return { success: true, userId: userId, username: username };
      } else {
        return { success: false, message: 'Usuário ou senha incorretos' };
      }
    } catch (error) {
      console.error('UserManager: Erro ao autenticar usuário:', error);
      return { success: false, message: 'Erro ao autenticar usuário' };
    }
  }

  /**
   * Desconecta o usuário atual
   * @returns {Promise} Promise que resolve quando o logout for concluído
   */
  async logoutUser() {
    try {
      await this.setStorageData({
        userLoggedIn: false,
        userId: null,
        username: null
      });
      
      this.currentUser = null;
      
      return { success: true };
    } catch (error) {
      console.error('UserManager: Erro ao desconectar usuário:', error);
      return { success: false, message: 'Erro ao desconectar usuário' };
    }
  }

  /**
   * Gera um ID único para usuário
   * @returns {String} ID único
   */
  generateUniqueId() {
    // Combinar timestamp com string aleatória
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substring(2, 10);
    return `user_${timestamp}_${randomStr}`;
  }

  /**
   * Função simples de hash para senhas
   * @param {String} password Senha a ser hasheada
   * @returns {String} Hash da senha
   */
  hashPassword(password) {
    // Esta é uma implementação simples para demonstração
    // Em produção, use uma biblioteca de hash segura
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
      const char = password.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Converter para inteiro de 32 bits
    }
    return hash.toString(16); // Converter para string hexadecimal
  }
}

// Exportar a classe UserManager
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UserManager;
} else {
  // Para uso no navegador
  window.UserManager = UserManager;
}
