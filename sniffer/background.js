// @ts-nocheck
// ==================== IMPORTAÇÃO DE CONFIGURAÇÕES ====================
try {
  importScripts('config.js', 'utils/encryption.js');
  console.log("config.js e encryption.js carregados com sucesso");
} catch (e) {
  console.error("Erro ao carregar config.js ou encryption.js:", e);
  // Fallback para valores padrão
  globalThis.API_ENDPOINT = "http://localhost:5000/data";
  globalThis.API_KEY = "12345abcde";
}

// ==================== CONFIGURAÇÕES ====================
const DATA_SEND_INTERVAL = 60000; // 1 minuto
const MAX_PENDING_DATA_COUNT = 100; // Enviar quando atingir este número
const CLEANUP_INTERVAL = 3600000; // 1 hora (limpar dados com mais de 24h)
const LOGIN_CHECK_INTERVAL = 300000; // 5 minutos
const API_HEALTH_CHECK_INTERVAL = 300000; // 5 minutos
const DIAGNOSTIC_INTERVAL = 300000; // 5 minutos

// ==================== VARIÁVEIS GLOBAIS ====================
let lastUploadAttempt = null;
let lastUploadSuccess = false;
let apiStatus = { online: false, lastCheck: null, error: null };
let lastDataSendTime = Date.now();
let pendingDataCount = 0;
let isInitialized = false;
let healthCheckTimer = null;

// Armazenamento de dados coletados
let cpctData = {
  requests: [],
  userActions: [],
  pageViews: [],
  errors: [],
  headers: [],
  metadata: [],
  profiles: [],
  documentContents: []
};

// ==================== VALIDAÇÃO DE CONTEXTO ====================
function isExtensionContextValid() {
  try {
    chrome.runtime.id;
    return true;
  } catch (e) {
    console.warn("Contexto da extensão de background invalidado");
    return false;
  }
}

// ==================== CLASSE USER MANAGER ====================
class UserManager {
  constructor() {
    this.currentUser = null;
    this.isInitialized = false;
    this.initializationPromise = null;
  }

  async initialize() {
    if (!isExtensionContextValid()) return;
    if (this.isInitialized) return;
    
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    
    this.initializationPromise = new Promise(async (resolve) => {
      try {
        console.log("UserManager: Iniciando inicialização...");
        const result = await this.getStorageData(["userLoggedIn", "userId", "username", "lastLogin"]);
        
        if (result.userLoggedIn && result.userId) {
          this.currentUser = {
            userId: result.userId,
            username: result.username,
            lastLogin: result.lastLogin
          };
          console.log("UserManager: Usuário já logado:", this.currentUser.username);
        } else {
          console.log("UserManager: Nenhum usuário logado");
        }
        
        this.isInitialized = true;
        resolve();
      } catch (error) {
        console.error("UserManager: Erro ao inicializar:", error);
        this.isInitialized = false;
        this.initializationPromise = null;
        resolve();
      }
    });
    
    return this.initializationPromise;
  }

  getStorageData(keys) {
    return new Promise((resolve, reject) => {
      if (!isExtensionContextValid()) {
        return reject(new Error("Contexto inválido"));
      }
      chrome.storage.local.get(keys, (result) => {
        if (chrome.runtime.lastError) {
          return reject(chrome.runtime.lastError);
        }
        resolve(result);
      });
    });
  }

  setStorageData(data) {
    return new Promise((resolve, reject) => {
      if (!isExtensionContextValid()) {
        return reject(new Error("Contexto inválido"));
      }
      chrome.storage.local.set(data, () => {
        if (chrome.runtime.lastError) {
          return reject(chrome.runtime.lastError);
        }
        resolve();
      });
    });
  }

  isUserLoggedIn() {
    return this.currentUser !== null;
  }

  getCurrentUserId() {
    return this.currentUser ? this.currentUser.userId : null;
  }

  getCurrentUsername() {
    return this.currentUser ? this.currentUser.username : null;
  }

  getCurrentUser() {
    return this.currentUser;
  }

  async registerUser(username, password) {
    if (!isExtensionContextValid()) return { success: false, message: "Contexto inválido" };
    try {
      const result = await this.getStorageData(["users"]);
      const users = result.users || {};
      
      if (users[username]) {
        return { success: false, message: "Este nome de usuário já está em uso" };
      }
      
      const userId = this.generateUniqueId();
      
      users[username] = {
        userId: userId,
        password: this.hashPassword(password),
        createdAt: new Date().toISOString()
      };
      
      await this.setStorageData({ users: users });
      
      return { success: true, userId: userId };
    } catch (error) {
      console.error("UserManager: Erro ao registrar usuário:", error);
      return { success: false, message: `Erro ao registrar usuário: ${error.message}` };
    }
  }

  async loginUser(username, password) {
    if (!isExtensionContextValid()) return { success: false, message: "Contexto inválido" };
    try {
      const result = await this.getStorageData(["users"]);
      const users = result.users || {};
      
      if (users[username] && users[username].password === this.hashPassword(password)) {
        const userId = users[username].userId;
        const loginTime = new Date().toISOString();
        
        await this.setStorageData({
          userLoggedIn: true,
          userId: userId,
          username: username,
          lastLogin: loginTime
        });
        
        this.currentUser = {
          userId: userId,
          username: username,
          lastLogin: loginTime
        };
        
        console.log("UserManager: Login bem-sucedido para:", username, "com ID:", userId);
        return { success: true, userId: userId, username: username };
      } else {
        return { success: false, message: "Usuário ou senha incorretos" };
      }
    } catch (error) {
      console.error("UserManager: Erro ao autenticar usuário:", error);
      return { success: false, message: `Erro ao autenticar usuário: ${error.message}` };
    }
  }

  async logoutUser() {
    if (!isExtensionContextValid()) return { success: false, message: "Contexto inválido" };
    try {
      await this.setStorageData({
        userLoggedIn: false,
        userId: null,
        username: null,
        lastLogin: null
      });
      
      this.currentUser = null;
      console.log("UserManager: Logout realizado.");
      return { success: true };
    } catch (error) {
      console.error("UserManager: Erro ao desconectar usuário:", error);
      return { success: false, message: `Erro ao desconectar usuário: ${error.message}` };
    }
  }

  generateUniqueId() {
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substring(2, 10);
    return `user_${timestamp}_${randomStr}`;
  }

  hashPassword(password) {
    let hash = 0;
    if (!password || typeof password !== "string") return "";
    for (let i = 0; i < password.length; i++) {
      const char = password.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }
}

// ==================== INSTÂNCIA GLOBAL DO USER MANAGER ====================
const userManager = new UserManager();

// ==================== FUNÇÕES DE INICIALIZAÇÃO ====================
async function initializeBackgroundScript() {
  if (!isExtensionContextValid()) {
    console.error("Contexto inválido durante a inicialização do background script.");
    return;
  }
  console.log("Background script inicializando...");
  
  try {
    await userManager.initialize();
    console.log("UserManager inicializado");
    
    const isLoggedIn = userManager.isUserLoggedIn();
    const userId = userManager.getCurrentUserId();
    console.log(`Status de login inicial: ${isLoggedIn ? `Logado (${userId})` : "Não logado"}`);
    
    isInitialized = true;
    console.log("Background script inicializado com sucesso.");
    
    if (pendingDataCount > 0) {
      console.log(`Dados pendentes (${pendingDataCount}) encontrados na inicialização. Tentando enviar...`);
      sendDataToServer();
    }
  } catch (error) {
    console.error("Erro fatal durante a inicialização do background script:", error);
  }

  setupListeners();
  setupPeriodicTasks();
}

// ==================== LISTENERS ====================
function setupListeners() {
  if (!isExtensionContextValid()) return;
  
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!isExtensionContextValid()) {
      console.warn("Contexto inválido ao receber mensagem.");
      return false;
    }
    
    const senderInfo = sender.tab ? `tab ${sender.tab.id} (${sender.tab.url?.substring(0, 50)}...)` : (sender.id ? `ext ${sender.id}` : "desconhecido");
    console.log(`[Background] Mensagem recebida: ${message?.action} de ${senderInfo}`, message?.data ? ` | Tipo de dados: ${message.data.type}` : "");
    
    let isAsync = false;
    try {
      switch (message.action) {
        case "ping":
          sendResponse({ status: "pong" });
          break;
        case "userAction":
          try {
            console.log(`[Background] Processando userAction tipo: ${message?.data?.type}`);
            const result = handleUserAction(message.data, sender.tab);
            sendResponse(result);
          } catch (error) {
            console.error("[Background] Erro síncrono ao processar userAction:", error, message?.data);
            sendResponse({ status: "error", message: error.message });
          }
          break;
        case "getCorrelationId":
          const correlationId = generateCorrelationId();
          sendResponse({ correlationId: correlationId });
          break;
        case "login":
          isAsync = true;
          handleLogin(message.username, message.password)
            .then(result => {
              if (isExtensionContextValid()) sendResponse(result);
            })
            .catch(error => {
              console.error("[Background] Erro ao processar login:", error);
              if (isExtensionContextValid()) sendResponse({ success: false, message: `Erro ao processar login: ${error.message || "Erro desconhecido"}` });
            });
          break;
        case "register":
          isAsync = true;
          handleRegister(message.username, message.password)
            .then(result => {
              if (isExtensionContextValid()) sendResponse(result);
            })
            .catch(error => {
              console.error("[Background] Erro ao processar registro:", error);
              if (isExtensionContextValid()) sendResponse({ success: false, message: `Erro ao processar registro: ${error.message || "Erro desconhecido"}` });
            });
          break;
        case "logout":
          isAsync = true;
          handleLogout()
            .then(result => {
              if (isExtensionContextValid()) sendResponse(result);
            })
            .catch(error => {
              console.error("[Background] Erro ao processar logout:", error);
              if (isExtensionContextValid()) sendResponse({ success: false, message: `Erro ao processar logout: ${error.message || "Erro desconhecido"}` });
            });
          break;
        case "checkLoginStatus":
          isAsync = true;
          checkLoginStatus()
            .then(result => {
              if (isExtensionContextValid()) sendResponse(result);
            })
            .catch(error => {
              console.error("[Background] Erro ao verificar status de login:", error);
              if (isExtensionContextValid()) sendResponse({ isLoggedIn: false, error: error.message || "Erro desconhecido" });
            });
          break;
        case "getDataStats":
          sendResponse({
            requestCount: cpctData.requests.length,
            userActionCount: cpctData.userActions.length,
            headerCount: cpctData.headers.length,
            metadataCount: cpctData.metadata.length,
            profileCount: cpctData.profiles.length,
            documentContentCount: cpctData.documentContents.length,
            errorCount: cpctData.errors.length,
            lastUploadAttempt: lastUploadAttempt,
            lastUploadSuccess: lastUploadSuccess,
            pendingDataCount: pendingDataCount
          });
          break;
        case "getCurrentData":
          const previewData = {
            requests: cpctData.requests.slice(-10),
            userActions: cpctData.userActions.slice(-10),
            headers: cpctData.headers.slice(-10),
            metadata: cpctData.metadata.slice(-10),
            profiles: cpctData.profiles.slice(-10),
            documentContents: cpctData.documentContents.slice(-10),
            errors: cpctData.errors.slice(-10)
          };
          sendResponse(previewData);
          break;
        case "getApiConfig":
          sendResponse({
            baseUrl: API_ENDPOINT,
            status: apiStatus
          });
          // Fazer uma verificação imediata quando solicitado
          checkApiStatus();
          break;
        case "forceUpload":
          isAsync = true;
          sendDataToServer(true)
            .then(result => {
              if (isExtensionContextValid()) sendResponse(result);
            })
            .catch(error => {
              console.error("[Background] Erro no forceUpload:", error);
              const errorMessage = error?.message || "Erro desconhecido durante o envio forçado.";
              if (isExtensionContextValid()) sendResponse({ success: false, message: errorMessage });
            });
          break;
        case "debugLoginStatus":
          isAsync = true;
          debugLoginStatus()
            .then(status => {
              if (isExtensionContextValid()) sendResponse(status);
            })
            .catch(error => {
              console.error("[Background] Erro no debugLoginStatus:", error);
              if (isExtensionContextValid()) sendResponse({ error: error.message || "Erro desconhecido" });
            });
          break;
        default:
          console.warn("[Background] Ação desconhecida recebida:", message.action);
          sendResponse({ status: "unknown_action" });
          break;
      }
    } catch (error) {
      console.error(`[Background] Erro ao processar mensagem ${message?.action}:`, error);
      try {
        if (!isAsync && isExtensionContextValid()) {
          sendResponse({ success: false, message: `Erro interno: ${error.message || "Erro desconhecido"}` });
        }
      } catch (e) {
        console.error("[Background] Erro ao enviar resposta de erro:", e);
      }
    }
    
    return isAsync;
  });
}

// ==================== TAREFAS PERIÓDICAS ====================
function setupPeriodicTasks() {
  if (!isExtensionContextValid()) return;
  
  // Envio periódico de dados
  setInterval(() => {
    if (!isExtensionContextValid()) return;
    if (isInitialized && pendingDataCount > 0 && 
        (pendingDataCount >= MAX_PENDING_DATA_COUNT || Date.now() - lastDataSendTime > DATA_SEND_INTERVAL)) {
      console.log(`[Background] Disparando envio periódico (Count: ${pendingDataCount}, Time since last: ${Date.now() - lastDataSendTime}ms)`);
      sendDataToServer();
    }
  }, DATA_SEND_INTERVAL / 2);

  // Limpeza periódica de dados antigos
  setInterval(() => {
    if (!isExtensionContextValid()) return;
    try {
      cleanupOldData();
    } catch (e) {
      console.error("[Background] Erro na limpeza periódica de dados:", e);
    }
  }, CLEANUP_INTERVAL);
  
  // Verificação periódica de login
  setInterval(async () => {
    if (!isExtensionContextValid()) return;
    try {
      await userManager.initialize(); 
      const isLoggedIn = userManager.isUserLoggedIn();
      const userId = userManager.getCurrentUserId();
      console.log(`[Background] Verificação periódica de login: ${isLoggedIn ? `Logado (${userId})` : "Não logado"}`);
    } catch (error) {
      console.error("[Background] Erro na verificação periódica de login:", error);
    }
  }, LOGIN_CHECK_INTERVAL);

  // Diagnóstico periódico
  setInterval(() => {
    if (!isExtensionContextValid()) return;
    try {
      logDiagnosticData();
    } catch (e) {
      console.error("[Background] Erro ao registrar dados de diagnóstico:", e);
    }
  }, DIAGNOSTIC_INTERVAL);

  // Iniciar verificação de saúde da API
  startApiHealthCheck();
}

// ==================== MANIPULAÇÃO DE DADOS ====================
function generateCorrelationId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

async function encryptActionData(action) {
  try {
    // Criptografa os dados sensíveis da ação
    const encryptedData = await Encryption.encryptData(action);
    
    // Retorna um objeto com os dados criptografados e metadados necessários
    return {
      type: action.type,
      timestamp: action.timestamp,
      userId: action.userId,
      tabId: action.tabId,
      encryptedData: encryptedData
    };
  } catch (error) {
    console.error("[Background] Erro ao criptografar dados:", error);
    throw error;
  }
}

async function handleUserAction(action, tab) {
  console.log("[Background] handleUserAction - Recebido tipo:", action?.type);
  
  if (!action || typeof action !== "object" || !action.type) {
    console.warn("[Background] handleUserAction - Recebida ação inválida ou sem tipo:", action);
    return { status: "error", message: "Ação inválida ou sem tipo" };
  }

  const userId = userManager && userManager.isUserLoggedIn() ? userManager.getCurrentUserId() : null;
  if (userId) {
    action.userId = userId;
  }
  
  if (tab) {
    action.tabId = tab.id;
  }
  
  if (!action.timestamp) {
    action.timestamp = new Date().toISOString();
  }
  
  let dataStored = false;
  let storedIn = "";

  try {
    // Criptografa os dados antes de armazenar
    const encryptedAction = await encryptActionData(action);

    if (action.type === "xhr" || action.type === "fetch" || 
        action.type === "xhrError" || action.type === "fetchError" ||
        action.type === "request" || action.type === "requestError") {
      cpctData.requests.push(encryptedAction);
      storedIn = "requests";
      dataStored = true;
    } else if (action.type === "header") {
      cpctData.headers.push(encryptedAction);
      storedIn = "headers";
      dataStored = true;
    } else if (action.type === "documentContent") {
      cpctData.documentContents.push(encryptedAction);
      storedIn = "documentContents";
      dataStored = true;
    } else if (action.type === "pageMetadata") {
      cpctData.metadata.push(encryptedAction);
      storedIn = "metadata";
      dataStored = true;
    } else if (action.type === "pageError" || action.type === "internalContentScriptError") {
      cpctData.errors.push(encryptedAction);
      storedIn = "errors";
      dataStored = true;
    } else if (action.type === "scriptInjected" || action.type === "contentScriptInitialized" || action.type === "diagnosticEvent") {
      cpctData.userActions.push(encryptedAction);
      storedIn = "userActions (system)";
      dataStored = true;
    } else {
      cpctData.userActions.push(encryptedAction);
      storedIn = "userActions (interaction)";
      dataStored = true;
    }
    
    if (dataStored) {
      pendingDataCount++;
      console.log(`[Background] handleUserAction - Ação tipo '${action.type}' armazenada em '${storedIn}'. Pending: ${pendingDataCount}`);
    } else {
      console.warn(`[Background] handleUserAction - Ação tipo '${action.type}' não foi armazenada.`);
    }
    
    if (dataStored && isInitialized && 
        (pendingDataCount >= MAX_PENDING_DATA_COUNT || Date.now() - lastDataSendTime > DATA_SEND_INTERVAL)) {
      console.log(`[Background] Disparando envio por handleUserAction (Count: ${pendingDataCount}, Time since last: ${Date.now() - lastDataSendTime}ms)`);
      sendDataToServer();
    }
    
    return { status: "received" };
  } catch (error) {
    console.error("[Background] Erro ao processar ação:", error);
    return { status: "error", message: "Erro ao processar ação" };
  }
}

// ==================== ENVIO DE DADOS ====================
async function sendDataToServer(forceUpload = false) {
  if (!isExtensionContextValid()) {
    console.warn("[Background] Contexto inválido ao tentar enviar dados.");
    return { success: false, message: "Contexto inválido" };
  }
  
  if (pendingDataCount === 0 && !forceUpload) {
    console.log("[Background] Nenhum dado pendente para enviar.");
    return { success: true, message: "Nenhum dado para enviar" };
  }
  
  if (!userManager.isInitialized) {
    try {
      console.log("[Background] UserManager não inicializado antes do envio, tentando inicializar...");
      await userManager.initialize();
      if (!userManager.isInitialized) {
        throw new Error("Falha ao inicializar UserManager antes do envio.");
      }
    } catch (error) {
      console.error("[Background] Erro ao inicializar UserManager antes do envio:", error);
      return { success: false, message: `Erro ao inicializar UserManager: ${error.message || "Erro desconhecido"}` };
    }
  }
  
  let effectiveUserId = userManager.getCurrentUserId();
  let effectiveUsername = userManager.getCurrentUsername();

  if (!effectiveUserId) {
    console.log("[Background] Usuário não está logado.");
    try {
      const storageData = await userManager.getStorageData(["userLoggedIn", "userId", "username", "lastLogin"]);
      if (storageData.userLoggedIn && storageData.userId) {
        console.log("[Background] Usuário encontrado no storage, atualizando UserManager.");
        userManager.currentUser = {
          userId: storageData.userId,
          username: storageData.username,
          lastLogin: storageData.lastLogin || new Date().toISOString()
        };
        effectiveUserId = storageData.userId;
        effectiveUsername = storageData.username;
      } else {
        if (!forceUpload) {
          console.log("[Background] Usuário não logado e envio não forçado. Dados não serão enviados.");
          return { success: false, message: "Usuário não está logado" };
        } else {
          console.log("[Background] Forçando envio mesmo sem usuário logado (modo de depuração).");
          effectiveUserId = "debug_user_" + Date.now();
          effectiveUsername = "debug_user";
        }
      }
    } catch (storageError) {
      console.error("[Background] Erro ao verificar storage antes de enviar:", storageError);
      if (!forceUpload) {
        return { success: false, message: `Erro ao verificar storage: ${storageError.message || "Erro desconhecido"}` };
      } else {
        console.log("[Background] Forçando envio mesmo com erro no storage (modo de depuração).");
        effectiveUserId = "debug_user_" + Date.now();
        effectiveUsername = "debug_user";
      }
    }
  }
  
  lastUploadAttempt = new Date().toISOString();
  
  const dataToSend = {
    userId: effectiveUserId,
    username: effectiveUsername,
    uploadTimestamp: new Date().toISOString(),
    userActions: [...cpctData.userActions],
    requests: [...cpctData.requests],
    errors: [...cpctData.errors],
    headers: [...cpctData.headers],
    metadata: [...cpctData.metadata],
    documentContents: [...cpctData.documentContents]
  };
  
  const totalItems = dataToSend.userActions.length + dataToSend.requests.length + 
                     dataToSend.errors.length + dataToSend.headers.length + 
                     dataToSend.metadata.length + dataToSend.documentContents.length;
  
  const dataSentSnapshot = { ...cpctData };
  const pendingCountBeforeSend = pendingDataCount;
  cpctData.userActions = [];
  cpctData.requests = [];
  cpctData.pageViews = [];
  cpctData.errors = [];
  cpctData.headers = [];
  cpctData.metadata = [];
  cpctData.profiles = [];
  cpctData.documentContents = [];
  pendingDataCount = 0;
  lastDataSendTime = Date.now();
  
  try {
    console.log(`[Background] Enviando ${totalItems} itens para API: ${API_ENDPOINT} (Usuário: ${effectiveUserId})`);
    
    // Não precisamos criptografar novamente, pois os dados já estão criptografados
    const response = await fetch(API_ENDPOINT+ "/data", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
      },
      body: JSON.stringify(dataToSend)
    });
    
    if (!response.ok) {
      let errorBody = "";
      try { errorBody = await response.text(); } catch {}
      throw new Error(`Erro na API: ${response.status} ${response.statusText}. ${errorBody}`);
    }
    
    const responseData = await response.json();
    console.log("[Background] Dados enviados com sucesso:", responseData);
    
    lastUploadSuccess = true;
    notifyPopup("uploadComplete", { success: true, timestamp: lastUploadAttempt, itemCount: totalItems });
    return { success: true, itemCount: totalItems, message: "Dados enviados com sucesso" };

  } catch (error) {
    console.error("[Background] Erro ao enviar dados:", error);
    
    console.log("[Background] Restaurando dados não enviados...");
    cpctData.userActions = [...dataSentSnapshot.userActions, ...cpctData.userActions];
    cpctData.requests = [...dataSentSnapshot.requests, ...cpctData.requests];
    cpctData.pageViews = [...dataSentSnapshot.pageViews, ...cpctData.pageViews];
    cpctData.errors = [...dataSentSnapshot.errors, ...cpctData.errors];
    cpctData.headers = [...dataSentSnapshot.headers, ...cpctData.headers];
    cpctData.metadata = [...dataSentSnapshot.metadata, ...cpctData.metadata];
    cpctData.profiles = [...dataSentSnapshot.profiles, ...cpctData.profiles];
    cpctData.documentContents = [...dataSentSnapshot.documentContents, ...cpctData.documentContents];
    
    pendingDataCount = cpctData.userActions.length + cpctData.requests.length + cpctData.errors.length + 
                       cpctData.headers.length + cpctData.metadata.length + cpctData.documentContents.length;
    console.log(`[Background] Dados restaurados. Contagem pendente: ${pendingDataCount}`);
    
    lastUploadSuccess = false;
    const errorMessage = error?.message || "Erro desconhecido durante o envio.";
    notifyPopup("uploadComplete", { success: false, timestamp: lastUploadAttempt, error: errorMessage });
    return { success: false, message: errorMessage };
  }
}

// ==================== LIMPEZA DE DADOS ====================
function cleanupOldData() {
  const now = Date.now();
  const maxAge = 24 * 60 * 60 * 1000; // 24 horas
  let cleanedCount = 0;
  
  function filterOldData(items) {
    if (!Array.isArray(items)) return [];
    const originalLength = items.length;
    const filtered = items.filter(item => {
      try {
        const timestamp = new Date(item.timestamp).getTime();
        return !isNaN(timestamp) && (now - timestamp) < maxAge;
      } catch {
        return false;
      }
    });
    cleanedCount += originalLength - filtered.length;
    return filtered;
  }
  
  console.log("[Background] Iniciando limpeza de dados antigos...");
  const oldPendingCount = pendingDataCount;
  
  cpctData.userActions = filterOldData(cpctData.userActions);
  cpctData.requests = filterOldData(cpctData.requests);
  cpctData.pageViews = filterOldData(cpctData.pageViews);
  cpctData.errors = filterOldData(cpctData.errors);
  cpctData.headers = filterOldData(cpctData.headers);
  cpctData.metadata = filterOldData(cpctData.metadata);
  cpctData.profiles = filterOldData(cpctData.profiles);
  cpctData.documentContents = filterOldData(cpctData.documentContents);
  
  pendingDataCount = cpctData.userActions.length + cpctData.requests.length + cpctData.errors.length + 
                     cpctData.headers.length + cpctData.metadata.length + cpctData.documentContents.length;
  
  if (cleanedCount > 0) {
    console.log(`[Background] Limpeza concluída. ${cleanedCount} itens removidos. Contagem pendente: ${pendingDataCount} (antes: ${oldPendingCount})`);
  }
}

// ==================== AUTENTICAÇÃO ====================
async function handleLogin(username, password) {
  if (!userManager) return { success: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize();
    const result = await userManager.loginUser(username, password);
    if (result.success && pendingDataCount > 0) {
      console.log("[Background] Login bem-sucedido, enviando dados pendentes...");
      setTimeout(() => sendDataToServer(), 500); 
    }
    return result;
  } catch (error) {
    console.error("[Background] Erro ao fazer login:", error);
    return { success: false, message: `Erro ao processar login: ${error.message || "Erro desconhecido"}` };
  }
}

async function handleRegister(username, password) {
  if (!userManager) return { success: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize();
    return await userManager.registerUser(username, password);
  } catch (error) {
    console.error("[Background] Erro ao registrar usuário:", error);
    return { success: false, message: `Erro ao processar registro: ${error.message || "Erro desconhecido"}` };
  }
}

async function handleLogout() {
  if (!userManager) return { success: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize();
    return await userManager.logoutUser();
  } catch (error) {
    console.error("[Background] Erro ao fazer logout:", error);
    return { success: false, message: `Erro ao processar logout: ${error.message || "Erro desconhecido"}` };
  }
}

async function checkLoginStatus() {
  if (!userManager) return { isLoggedIn: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize();
    const isLoggedIn = userManager.isUserLoggedIn();
    const userId = userManager.getCurrentUserId();
    const username = userManager.getCurrentUsername();
    console.log(`[Background] Verificação de status de login: ${isLoggedIn ? `Logado (${userId})` : "Não logado"}`);
    return {
      isLoggedIn: isLoggedIn,
      userId: userId,
      username: username
    };
  } catch (error) {
    console.error("[Background] Erro ao verificar status de login:", error);
    return { isLoggedIn: false, error: error.message || "Erro desconhecido" };
  }
}

// ==================== DIAGNÓSTICO E UTILITÁRIOS ====================
function logDiagnosticData() {
  if (!isExtensionContextValid()) return;
  
  const stats = {
    timestamp: new Date().toISOString(),
    isInitialized: isInitialized,
    userManagerInitialized: userManager ? userManager.isInitialized : false,
    isUserLoggedIn: userManager ? userManager.isUserLoggedIn() : false,
    userId: userManager ? userManager.getCurrentUserId() : null,
    pendingDataCount: pendingDataCount,
    lastDataSendTime: lastDataSendTime ? new Date(lastDataSendTime).toISOString() : null,
    lastUploadAttempt: lastUploadAttempt,
    lastUploadSuccess: lastUploadSuccess,
    counts: {
      requests: cpctData.requests.length,
      userActions: cpctData.userActions.length,
      headers: cpctData.headers.length,
      metadata: cpctData.metadata.length,
      documentContents: cpctData.documentContents.length,
      errors: cpctData.errors.length
    }
  };

  console.log("[Background] Diagnóstico:", stats);
  
  if (cpctData.requests.length > 0) {
    const requestTypes = cpctData.requests.reduce((acc, req) => {
      const type = req.type || "unknown";
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});
    console.log("[Background] Tipos de requisições pendentes:", requestTypes);
  }
  
  if (cpctData.errors.length > 0) {
    const errorTypes = cpctData.errors.reduce((acc, err) => {
      const type = err.type || "unknownError";
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});
    console.log("[Background] Tipos de erros pendentes:", errorTypes);
  }
}

function notifyPopup(action, data) {
  if (!isExtensionContextValid()) return;
  try {
    chrome.runtime.sendMessage({ action: action, data: data }, response => {
      if (chrome.runtime.lastError) {
        // Comum se o popup não estiver aberto
      }
    });
  } catch (error) {
    console.warn("[Background] Erro ao tentar notificar popup:", error);
  }
}

async function debugLoginStatus() {
  if (!isExtensionContextValid()) return { error: "Contexto inválido" };
  const status = {
    isInitialized: isInitialized,
    userManagerInitialized: userManager.isInitialized,
    isLoggedIn: userManager.isUserLoggedIn(),
    userId: userManager.getCurrentUserId(),
    username: userManager.getCurrentUsername(),
    currentUserObject: userManager.getCurrentUser(),
    storageData: null,
    error: null
  };
  try {
    status.storageData = await userManager.getStorageData(["userLoggedIn", "userId", "username", "lastLogin", "users"]);
  } catch (e) {
    status.error = `Erro ao ler storage: ${e.message || "Erro desconhecido"}`;
  }
  console.log("[Background] Debug Login Status:", status);
  return status;
}

// ==================== VERIFICAÇÃO DO STATUS DA API ====================
async function checkApiStatus() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 segundos timeout

    const response = await fetch(API_ENDPOINT + "/health", {
      method: "GET",
      headers: {
        "X-API-Key": API_KEY
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    apiStatus.online = response.ok;
    apiStatus.lastCheck = new Date().toISOString();
    apiStatus.error = response.ok ? null : `Status ${response.status}`;

    console.log(`[Background] API status check: ${apiStatus.online ? "Online" : "Offline"}`);
    
    // Notificar o popup se estiver aberto
    notifyPopup("apiStatusUpdate", apiStatus);

  } catch (error) {
    apiStatus.online = false;
    apiStatus.lastCheck = new Date().toISOString();
    apiStatus.error = error.name === 'AbortError' ? 'Timeout' : error.message;
    
    console.log(`[Background] API status check failed: ${apiStatus.error}`);
    
    // Notificar o popup se estiver aberto
    notifyPopup("apiStatusUpdate", apiStatus);
  }
  
  return apiStatus;
}

function startApiHealthCheck() {
  // Limpar timer existente se houver
  if (healthCheckTimer) {
    clearInterval(healthCheckTimer);
  }
  
  // Fazer verificação inicial
  checkApiStatus();
  
  // Configurar verificação periódica
  healthCheckTimer = setInterval(checkApiStatus, API_HEALTH_CHECK_INTERVAL);
}

async function addRequest(request) {
    try {
        // Validação básica
        if (!request || !request.url || !request.timestamp) {
            console.error('Requisição inválida:', request);
            return;
        }

        // Criptografa os dados antes de armazenar
        const encryptedData = await Encryption.encryptData(JSON.stringify(request));
        
        // Armazena os dados criptografados
        cpctData.requests.push({
            ...request,
            encryptedData: encryptedData
        });

        // Salva backup local
        await saveBackup();
        
        // Verifica se deve enviar
        if (shouldSendData()) {
            await sendDataToServer();
        }
    } catch (error) {
        console.error('Erro ao adicionar requisição:', error);
    }
}

async function addUserAction(action) {
    try {
        // Validação básica
        if (!action || !action.type || !action.timestamp) {
            console.error('Ação inválida:', action);
            return;
        }

        // Criptografa os dados antes de armazenar
        const encryptedData = await Encryption.encryptData(JSON.stringify(action));
        
        // Armazena os dados criptografados
        cpctData.userActions.push({
            ...action,
            encryptedData: encryptedData
        });

        // Salva backup local
        await saveBackup();
        
        // Verifica se deve enviar
        if (shouldSendData()) {
            await sendDataToServer();
        }
    } catch (error) {
        console.error('Erro ao adicionar ação:', error);
    }
}

// ==================== INICIALIZAÇÃO DO SCRIPT ====================
initializeBackgroundScript();
// A verificação inicial da API agora é feita dentro de startApiHealthCheck()