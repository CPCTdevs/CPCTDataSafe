// @ts-nocheck
// ==================== IMPORTAÇÃO DE CONFIGURAÇÕES ====================
try {
  importScripts('config.js', 'utils/encryption.js');
  console.log("config.js e encryption.js carregados com sucesso");
} catch (e) {
  console.error("Erro ao carregar config.js ou encryption.js:", e);
  // Fallback para valores padrão
  globalThis.API_ENDPOINT = "https://143.107.95.250:8443";
  globalThis.API_KEY = "abcd123";
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
let processedRequests = new Set();

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

// === NOVO: Persistência no chrome.storage.local ===
async function loadPersistedData() {
  try {
    if (!isExtensionContextValid()) return;
    const result = await new Promise((resolve, reject) => {
      chrome.storage.local.get("cpctData", (res) => {
        if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
        resolve(res);
      });
    });
    if (result && result.cpctData) {
      cpctData = result.cpctData;
      pendingDataCount = cpctData.userActions.length + cpctData.requests.length + cpctData.errors.length +
                         cpctData.headers.length + cpctData.metadata.length + cpctData.documentContents.length;
      console.log(`[Background] Dados carregados do storage. Itens pendentes: ${pendingDataCount}`);
    }
  } catch (e) {
    console.error("[Background] Erro ao carregar cpctData do storage:", e);
  }
}

async function persistCurrentData() {
  try {
    if (!isExtensionContextValid()) return;
    await new Promise((resolve, reject) => {
      chrome.storage.local.set({ cpctData }, () => {
        if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
        resolve();
      });
    });
    console.log("[Background] cpctData persistido no storage.");
  } catch (e) {
    console.error("[Background] Erro ao persistir cpctData:", e);
  }
}

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
        createdAt: getCompatibleTimestamp()
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
        const loginTime = getCompatibleTimestamp();
        
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
  // Carrega dados persistidos antes de qualquer outra operação
  await loadPersistedData();
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
      console.warn("[Background] Contexto inválido ao receber mensagem.");
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
              if (isExtensionContextValid()) {
                sendResponse(result);
              } else {
                console.warn("[Background] Contexto inválido ao enviar resposta de login");
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao processar login:", error);
              if (isExtensionContextValid()) {
                sendResponse({ success: false, message: `Erro ao processar login: ${error.message || "Erro desconhecido"}` });
              }
            });
          break;
        case "register":
          isAsync = true;
          handleRegister(message.username, message.email, message.password)
            .then(result => {
              if (isExtensionContextValid()) {
                sendResponse(result);
              } else {
                console.warn("[Background] Contexto inválido ao enviar resposta de registro");
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao processar registro:", error);
              if (isExtensionContextValid()) {
                sendResponse({ success: false, message: `Erro ao processar registro: ${error.message || "Erro desconhecido"}` });
              }
            });
          break;
        case "logout":
          isAsync = true;
          handleLogout()
            .then(result => {
              if (isExtensionContextValid()) {
                sendResponse(result);
              } else {
                console.warn("[Background] Contexto inválido ao enviar resposta de logout");
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao processar logout:", error);
              if (isExtensionContextValid()) {
                sendResponse({ success: false, message: `Erro ao processar logout: ${error.message || "Erro desconhecido"}` });
              }
            });
          break;
        case "checkLoginStatus":
          isAsync = true;
          checkLoginStatus()
            .then(result => {
              if (isExtensionContextValid()) {
                sendResponse(result);
              } else {
                console.warn("[Background] Contexto inválido ao enviar status de login");
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao verificar status de login:", error);
              if (isExtensionContextValid()) {
                sendResponse({ isLoggedIn: false, error: error.message || "Erro desconhecido" });
              }
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
          isAsync = true;
          (async () => {
            let dataRef = cpctData;
            const totalBuffered = dataRef.userActions.length + dataRef.requests.length + dataRef.documentContents.length;
            if (totalBuffered === 0) {
              try {
                const stored = await new Promise((resolve, reject) => {
                  chrome.storage.local.get("cpctData", (res) => {
                    if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
                    resolve(res);
                  });
                });
                if (stored && stored.cpctData) {
                  dataRef = stored.cpctData;
                }
              } catch (e) {
                console.error("[Background] Erro ao recuperar cpctData do storage para preview:", e);
              }
            }

            const previewData = {
              requests: (dataRef.requests || []).slice(-10),
              userActions: (dataRef.userActions || []).slice(-10),
              headers: (dataRef.headers || []).slice(-10),
              metadata: (dataRef.metadata || []).slice(-10),
              profiles: (dataRef.profiles || []).slice(-10),
              documentContents: (dataRef.documentContents || []).slice(-10),
              errors: (dataRef.errors || []).slice(-10)
            };
            if (isExtensionContextValid()) sendResponse(previewData);
          })();
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
        case "getAuthStatus":
          isAsync = true;
          checkLoginStatus()
            .then(result => {
              if (isExtensionContextValid()) {
                sendResponse({ 
                  isAuthenticated: result.isLoggedIn,
                  user: result.username ? { username: result.username, id: result.userId } : null,
                  userId: result.userId,
                  apiAuth: result.apiAuth,
                  localAuth: result.localAuth
                });
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao verificar auth status:", error);
              if (isExtensionContextValid()) {
                sendResponse({ 
                  isAuthenticated: false, 
                  error: error.message 
                });
              }
            });
          break;
        case "checkApiStatus":
          isAsync = true;
          checkApiStatus()
            .then(result => {
              if (isExtensionContextValid()) {
                sendResponse(result);
              }
            })
            .catch(error => {
              console.error("[Background] Erro ao verificar status da API:", error);
              if (isExtensionContextValid()) {
                sendResponse({ 
                  isOnline: false, 
                  error: error.message 
                });
              }
            });
          break;
        default:
          console.warn(`[Background] Ação desconhecida: ${message.action}`);
          sendResponse({ status: "error", message: "Ação desconhecida" });
      }
    } catch (error) {
      console.error("[Background] Erro ao processar mensagem:", error);
      if (isExtensionContextValid()) {
        sendResponse({ status: "error", message: error.message || "Erro desconhecido" });
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
    // Verifica se a chave RSA está disponível
    try {
      const keyUrl = chrome.runtime.getURL('keys/rsa_public.pem');
      const response = await fetch(keyUrl);
      if (!response.ok) {
        throw new Error('Chave não encontrada');
      }
      
      // Se chegou aqui, a chave existe - usa criptografia
      const encryptedData = await Encryption.encryptData(action);
      
      // Converter dados criptografados para formato da API
      return convertToApiFormat(action, { encryptedData });
    } catch (keyError) {
      console.warn("[Background] Chave RSA não encontrada, enviando dados sem criptografia:", keyError.message);
      
      // Converter dados não criptografados para formato da API  
      return convertToApiFormat(action, action);
    }
  } catch (error) {
    console.error("[Background] Erro ao processar dados:", error);
    throw error;
  }
}

function convertToApiFormat(originalAction, dataPayload) {
  const baseObject = {
    type: originalAction.type,
    timestamp: originalAction.timestamp || getCompatibleTimestamp(),
    correlationId: originalAction.correlationId || `${originalAction.type}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  };

  // Para userActions
  if (originalAction.type === "click" || originalAction.type === "input" || originalAction.type === "keyInput" ||
      originalAction.type === "scroll" || originalAction.type === "keypress" || originalAction.type === "keyDownSpecific" ||
      originalAction.type === "change" || originalAction.type === "windowFocus" || originalAction.type === "windowBlur" ||
      originalAction.type === "scriptInjected" || originalAction.type === "contentScriptInitialized" ||
      originalAction.type === "diagnosticEvent") {
    
    const result = { ...baseObject };
    
    // Adicionar pageContext se disponível (incluindo do enrichedAction)
    if (originalAction.pageContext) {
      result.url = originalAction.pageContext.url;
      result.pageTitle = originalAction.pageContext.title;
      result.pageContext = originalAction.pageContext;
    } else if (originalAction.url || originalAction.pageTitle) {
      result.url = originalAction.url || "";
      result.pageTitle = originalAction.pageTitle || "";
      result.pageContext = {
        url: originalAction.url || "",
        title: originalAction.pageTitle || ""
      };
    }
    
    // Adicionar target para interações (incluindo todas as propriedades)
    if (originalAction.target) {
      result.targetTag = originalAction.target.tagName;
      result.targetSelector = originalAction.target.selector;
      result.targetText = dataPayload.encryptedData ? "[ENCRYPTED]" : originalAction.target.text;
      result.target = originalAction.target;
    } else if (originalAction.tagName || originalAction.selector || originalAction.targetText) {
      result.targetTag = originalAction.tagName || "unknown";
      result.targetSelector = originalAction.selector || "";
      result.targetText = dataPayload.encryptedData ? "[ENCRYPTED]" : (originalAction.targetText || "");
      result.target = {
        tagName: originalAction.tagName || "unknown",
        selector: originalAction.selector || "",
        text: dataPayload.encryptedData ? "[ENCRYPTED]" : (originalAction.targetText || "")
      };
    }
    
    // Adicionar value para inputs
    if (originalAction.value !== undefined) {
      result.inputValue = dataPayload.encryptedData ? "[ENCRYPTED]" : originalAction.value;
      result.value = dataPayload.encryptedData ? "[ENCRYPTED]" : originalAction.value;
    }
    
    // Adicionar key para keypresses
    if (originalAction.key) {
      result.keyPressed = originalAction.key;
      result.key = originalAction.key;
    }
    
    // Adicionar scrollPosition para scroll
    if (originalAction.scrollPosition) {
      result.scrollX = originalAction.scrollPosition.x;
      result.scrollY = originalAction.scrollPosition.y;
      result.scrollPosition = originalAction.scrollPosition;
    } else if (originalAction.scrollX !== undefined || originalAction.scrollY !== undefined) {
      result.scrollX = originalAction.scrollX || 0;
      result.scrollY = originalAction.scrollY || 0;
      result.scrollPosition = {
        x: originalAction.scrollX || 0,
        y: originalAction.scrollY || 0
      };
    }

    // Adicionar posição do clique
    if (originalAction.position) {
      result.clickX = originalAction.position.x;
      result.clickY = originalAction.position.y;
      result.position = originalAction.position;
    }
    
    // Log de debug para verificação
    console.log(`[Background] convertToApiFormat - ${originalAction.type}:`, {
      url: result.url,
      pageTitle: result.pageTitle,
      targetTag: result.targetTag,
      targetSelector: result.targetSelector,
      targetText: result.targetText,
      inputValue: result.inputValue,
      keyPressed: result.keyPressed,
      scrollX: result.scrollX,
      scrollY: result.scrollY
    });
    
    return result;
  }
  
  // Para requests
  if (originalAction.type === "xhr" || originalAction.type === "fetch" || 
      originalAction.type === "request" || originalAction.type === "xhrError" || 
      originalAction.type === "fetchError" || originalAction.type === "requestError") {
    
    return {
      url: (originalAction.url || "").slice(0, 500),
      method: originalAction.method || "GET",
      statusCode: originalAction.statusCode || originalAction.status || 0,
      timestamp: baseObject.timestamp,
      requestId: originalAction.requestId || baseObject.correlationId
    };
  }
  
  // Para documentContents
  if (originalAction.type === "documentContent" || originalAction.type === "page_load") {
    const result = {
      type: "page_load",
      timestamp: baseObject.timestamp,
      correlationId: baseObject.correlationId
    };
    
    if (originalAction.url || originalAction.pageTitle) {
      result.pageContext = {
        url: originalAction.url || "",
        title: originalAction.pageTitle || ""
      };
    }
    
    return result;
  }
  
  // Fallback para outros tipos
  return {
    ...baseObject,
    rawData: dataPayload.encryptedData || dataPayload
  };
}

async function handleUserAction(action, tab) {
  console.log("[Background] handleUserAction - Recebido tipo:", action?.type);
  
  if (!action || typeof action !== "object" || !action.type) {
    console.warn("[Background] handleUserAction - Recebida ação inválida ou sem tipo:", action);
    return { status: "error", message: "Ação inválida ou sem tipo" };
  }

  // Add deduplication for fetch/xhr requests
  if (action.type === "fetch" || action.type === "xhr") {
    const requestKey = `${action.type}_${action.requestId || action.url}_${action.timestamp}`;
    if (processedRequests.has(requestKey)) {
      console.log(`[Background] Ignorando requisição duplicada: ${requestKey}`);
      return { status: "duplicate" };
    }
    processedRequests.add(requestKey);
    // Clean up old requests after 5 minutes
    setTimeout(() => processedRequests.delete(requestKey), 5 * 60 * 1000);
  }

  const userId = userManager && userManager.isUserLoggedIn() ? userManager.getCurrentUserId() : null;
  if (userId) {
    action.userId = userId;
  }
  
  if (tab) {
    action.tabId = tab.id;
  }
  
  if (!action.timestamp) {
    action.timestamp = getCompatibleTimestamp();
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
      // Persistir dados após cada ação armazenada
      persistCurrentData();
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
          lastLogin: storageData.lastLogin || getCompatibleTimestamp()
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
  
  lastUploadAttempt = getCompatibleTimestamp();
  
  const dataToSend = {
    userActions: [...cpctData.userActions],
    requests: [...cpctData.requests],
    documentContents: [...cpctData.documentContents]
  };
  
  const totalItems = dataToSend.userActions.length + dataToSend.requests.length + 
                     dataToSend.documentContents.length;
  
  console.log(`[Background] 📊 Preparando dados para envio:`, {
    userActions: dataToSend.userActions.length,
    requests: dataToSend.requests.length, 
    documentContents: dataToSend.documentContents.length,
    totalItems: totalItems
  });
  
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
    console.log(`[Background] 📤 Enviando ${totalItems} itens (Usuário: ${effectiveUserId})`);
    
    // Obter token de autorização
    const authData = await chrome.storage.local.get('auth');
    const token = authData.auth?.token;
    
    if (!token) {
      console.error("[Background] Token não encontrado no storage:", authData);
      throw new Error("Token de autorização não encontrado. Usuário precisa fazer login novamente.");
    }
    
    console.log(`[Background] Token encontrado, enviando dados para servidor...`);
    
    // Criptografar todo o lote com a chave pública RSA
    const encryptedPackage = await Encryption.encryptData(dataToSend);
    const dataPayload = JSON.stringify(encryptedPackage);
    // Log para verificação (mostrar apenas primeiros 300 caracteres)
    console.log('[Background] 🚀 Payload JSON (truncate):', dataPayload.substring(0, 300) + (dataPayload.length > 300 ? '...' : ''));
    console.log(`[Background] 📦 Payload criptografado: ${encryptedPackage.chunks.length} chunks, JSON ${dataPayload.length} bytes`);
    
    // Primeiro: tentar HTTPS direto com configurações otimizadas para extensões
    try {
      console.log("[Background] 🔒 Tentativa 1: HTTPS direto com configurações de extensão...");
      
      const httpsResponse = await fetch(`${API_ENDPOINT}/data`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
          "X-API-Key": API_KEY,
          "User-Agent": "CPCT-Extension/1.0",
          "Accept": "application/json"
        },
        body: dataPayload,
        credentials: 'omit',
        cache: 'no-cache',
        mode: 'cors'
      });
      
      console.log(`[Background] ✅ HTTPS respondeu: ${httpsResponse.status}`);
      
      if (httpsResponse.ok) {
        let responseData;
        try {
          responseData = await httpsResponse.json();
          console.log("[Background] ✅ Dados enviados com sucesso via HTTPS:", responseData);
        } catch (jsonError) {
          console.log("[Background] ⚠️ HTTPS aceitou dados mas resposta não é JSON");
          responseData = { status: 'success', note: 'Resposta não-JSON' };
        }
        
        lastUploadSuccess = true;
        notifyPopup("uploadComplete", { 
          success: true, 
          timestamp: lastUploadAttempt, 
          itemCount: totalItems,
          endpoint: `${API_ENDPOINT}/data`,
          method: 'HTTPS direto'
        });
        
        // Atualiza storage para refletir que os dados foram enviados/limpos
        persistCurrentData();
        
        return { 
          success: true, 
          itemCount: totalItems, 
          message: "Dados enviados com sucesso via HTTPS",
          endpoint: `${API_ENDPOINT}/data`
        };
      } else {
        throw new Error(`HTTPS retornou ${httpsResponse.status}: ${await httpsResponse.text()}`);
      }
      
    } catch (httpsError) {
      console.log("[Background] ❌ HTTPS falhou:", httpsError.message);
      
      if (httpsError.message.includes('Failed to fetch')) {
        console.log("[Background] 🔒 Problema de certificado detectado, tentando abordagem alternativa...");
        
        // Segundo: tentar via HTTP com redirecionamento automático
        try {
          console.log("[Background] 🔄 Tentativa 2: HTTP com redirecionamento automático...");
          
          const httpResponse = await fetch(`${API_ENDPOINT_HTTP_FALLBACK}/data`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${token}`,
              "X-API-Key": API_KEY,
              "User-Agent": "CPCT-Extension/1.0"
            },
            body: dataPayload,
            credentials: 'omit',
            cache: 'no-cache',
            redirect: 'follow' // Seguir redirecionamentos
          });
          
          console.log(`[Background] HTTP resposta: ${httpResponse.status}`);
          console.log(`[Background] HTTP URL final: ${httpResponse.url}`);
          
          if (httpResponse.ok) {
            let responseData;
            try {
              responseData = await httpResponse.json();
              console.log("[Background] ✅ Dados enviados com sucesso via HTTP→HTTPS:", responseData);
            } catch (jsonError) {
              console.log("[Background] ⚠️ Redirecionamento aceitou dados mas resposta não é JSON");
              responseData = { status: 'success', note: 'Resposta não-JSON via redirecionamento' };
            }
            
            lastUploadSuccess = true;
            notifyPopup("uploadComplete", { 
              success: true, 
              timestamp: lastUploadAttempt, 
              itemCount: totalItems,
              endpoint: httpResponse.url,
              method: 'HTTP→HTTPS redirecionamento'
            });
            
            // Atualiza storage para refletir que os dados foram enviados/limpos
            persistCurrentData();
            
            return { 
              success: true, 
              itemCount: totalItems, 
              message: "Dados enviados com sucesso via redirecionamento HTTP→HTTPS",
              endpoint: httpResponse.url
            };
          } else {
            throw new Error(`HTTP redirecionamento retornou ${httpResponse.status}: ${await httpResponse.text()}`);
          }
          
        } catch (httpError) {
          console.log("[Background] ❌ HTTP redirecionamento também falhou:", httpError.message);
          throw new Error(`Ambas tentativas falharam - HTTPS: ${httpsError.message}, HTTP: ${httpError.message}`);
        }
      } else {
        // Se não é problema de certificado, não tentar HTTP
        throw httpsError;
      }
    }

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
    
    // Persistir estado restaurado
    persistCurrentData();
    
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
  console.log(`[Background] 🔐 Iniciando login para usuário: ${username}`);
  
  // Lista de endpoints para tentar
  const loginEndpoints = [
    { url: AUTH_ENDPOINTS.LOGIN, description: 'HTTPS Login', type: 'https' },
    { url: AUTH_ENDPOINTS.LOGIN_HTTP, description: 'HTTP Login', type: 'http' }
  ];
  
  for (const endpoint of loginEndpoints) {
    try {
      console.log(`[Background] 📡 Tentando ${endpoint.description}: ${endpoint.url}`);
      
      const payload = { username, password };
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(payload)
      });

      console.log(`[Background] Resposta de ${endpoint.description} - Status: ${response.status} ${response.statusText}`);

      // Get response text first to debug
      const responseText = await response.text();
      console.log(`[Background] Texto da resposta de ${endpoint.description}:`, responseText);

      if (!response.ok) {
        let error;
        try {
          error = JSON.parse(responseText);
          console.log(`[Background] Erro parseado de ${endpoint.description}:`, error);
        } catch (e) {
          console.log(`[Background] Erro ao fazer parse do erro de ${endpoint.description}:`, e);
          // Se esse endpoint falhou, tentar o próximo
          if (endpoint.type === 'https') {
            console.log(`[Background] ⚠️ HTTPS falhou, tentando HTTP...`);
            continue;
          } else {
            throw new Error(`${response.status}: ${responseText}`);
          }
        }
        // Se esse endpoint falhou mas conseguimos parsear o erro, tentar próximo se for HTTPS
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS retornou erro, tentando HTTP...`);
          continue;
        } else {
          throw new Error(error.error || error.message || 'Login failed');
        }
      }

      // Try to parse response as JSON
      let data;
      try {
        data = JSON.parse(responseText);
        console.log(`[Background] Dados de login parseados de ${endpoint.description}:`, data);
      } catch (e) {
        console.error(`[Background] Erro ao fazer parse da resposta de sucesso de ${endpoint.description}:`, e);
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS com resposta inválida, tentando HTTP...`);
          continue;
        } else {
          throw new Error(`Resposta inválida: ${responseText}`);
        }
      }
      
      // Store auth data for API
      console.log(`[Background] ✅ Login bem-sucedido via ${endpoint.description}, salvando dados...`);
      await chrome.storage.local.set({
        'auth': {
          token: data.access_token,
          user: data.user,
          timestamp: Date.now(),
          endpoint: endpoint.url // Salvar qual endpoint funcionou
        }
      });

      // Also update UserManager for compatibility
      const userId = data.user?.id || `api_user_${Date.now()}`;
      const loginTime = getCompatibleTimestamp();
      
      console.log(`[Background] Atualizando UserManager com userId: ${userId}`);
      
      await userManager.setStorageData({
        userLoggedIn: true,
        userId: userId,
        username: username,
        lastLogin: loginTime
      });
      
      userManager.currentUser = {
        userId: userId,
        username: username,
        lastLogin: loginTime
      };

      console.log(`[Background] ✅ Login completo via ${endpoint.description}: ${username} (${userId})`);
      
      return {
        success: true,
        access_token: data.access_token,
        user: data.user,
        userId: userId,
        username: username,
        endpoint: endpoint.url,
        usingFallback: endpoint.type === 'http'
      };
      
    } catch (error) {
      console.error(`[Background] Erro em ${endpoint.description}:`, error.message);
      
      // Se for HTTPS e erro de fetch, tentar HTTP
      if (endpoint.type === 'https' && error.message.includes('Failed to fetch')) {
        console.log(`[Background] 🔒 Problema de certificado em HTTPS, tentando HTTP...`);
        continue;
      } else if (endpoint.type === 'http') {
        // Se HTTP também falhou, é erro definitivo
        console.error('[Background] Ambos endpoints de login falharam');
        throw error;
      }
    }
  }
  
  // Se chegou aqui, todos os endpoints falharam
  throw new Error('Todos os endpoints de login falharam');
}

async function handleRegister(username, email, password) {
  console.log("[Background] 📝 Iniciando registro para:", { username, email });
  
  // Lista de endpoints para tentar
  const registerEndpoints = [
    { url: AUTH_ENDPOINTS.REGISTER, description: 'HTTPS Register', type: 'https' },
    { url: AUTH_ENDPOINTS.REGISTER_HTTP, description: 'HTTP Register', type: 'http' }
  ];
  
  // Validate inputs
  if (!username || !email || !password) {
    throw new Error("Todos os campos são obrigatórios");
  }

  // Prepare request data
  const requestData = {
    username: username.trim(),
    email: email.trim(),
    password: password,
    role: 'user'
  };
  
  for (const endpoint of registerEndpoints) {
    try {
      console.log(`[Background] 📡 Tentando ${endpoint.description}: ${endpoint.url}`);
      
      // Log the full request details
      console.log(`[Background] Detalhes da requisição para ${endpoint.description}:`, {
        url: endpoint.url,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
          'Accept': 'application/json'
        },
        body: requestData
      });

      // Make the request
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
          'Accept': 'application/json'
        },
        body: JSON.stringify(requestData)
      });

      // Log response details
      console.log(`[Background] Detalhes da resposta de ${endpoint.description}:`, {
        status: response.status,
        statusText: response.statusText,
        contentType: response.headers.get('content-type'),
        headers: Object.fromEntries(response.headers.entries())
      });

      // Get response text first
      const responseText = await response.text();
      console.log(`[Background] Resposta de ${endpoint.description}:`, responseText);

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        console.error(`[Background] Resposta de ${endpoint.description} não é JSON:`, {
          contentType,
          responseText: responseText.substring(0, 500)
        });
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS com resposta não-JSON, tentando HTTP...`);
          continue;
        } else {
          throw new Error(`Resposta inválida do servidor (${response.status}): ${responseText.substring(0, 100)}...`);
        }
      }

      // Try to parse as JSON
      let data;
      try {
        data = JSON.parse(responseText);
      } catch (e) {
        console.error(`[Background] Erro ao fazer parse da resposta de ${endpoint.description} como JSON:`, {
          error: e.message,
          responseText: responseText.substring(0, 500)
        });
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS com JSON inválido, tentando HTTP...`);
          continue;
        } else {
          throw new Error(`Resposta inválida do servidor (${response.status}): ${responseText.substring(0, 100)}...`);
        }
      }

      // Handle specific error cases
      if (response.status === 400) {
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS retornou 400, tentando HTTP...`);
          continue;
        }
        throw new Error(data.error || "Dados inválidos");
      }
      
      if (response.status === 409) {
        // Este erro é definitivo, não tentar outro endpoint
        throw new Error(data.error || "Usuário ou email já existe");
      }

      if (!response.ok) {
        if (endpoint.type === 'https') {
          console.log(`[Background] ⚠️ HTTPS retornou ${response.status}, tentando HTTP...`);
          continue;
        }
        throw new Error(data.error || data.message || `Erro no registro: ${response.status} ${response.statusText}`);
      }

      console.log(`[Background] ✅ Registro bem-sucedido via ${endpoint.description}`);
      return {
        success: true,
        message: data.message || "Registro realizado com sucesso",
        endpoint: endpoint.url,
        usingFallback: endpoint.type === 'http'
      };
      
    } catch (error) {
      console.error(`[Background] Erro em ${endpoint.description}:`, {
        error: error.message,
        stack: error.stack,
        requestData: { username, email, password: '***' }
      });
      
      // Se for HTTPS e erro de fetch, tentar HTTP
      if (endpoint.type === 'https' && error.message.includes('Failed to fetch')) {
        console.log(`[Background] 🔒 Problema de certificado em HTTPS, tentando HTTP...`);
        continue;
      } else if (endpoint.type === 'http') {
        // Se HTTP também falhou, é erro definitivo
        console.error('[Background] Ambos endpoints de registro falharam');
        throw error;
      }
      
      // Se é um erro específico (como 409), não tentar outro endpoint
      if (error.message.includes('já existe')) {
        throw error;
      }
    }
  }
  
  // Se chegou aqui, todos os endpoints falharam
  throw new Error('Todos os endpoints de registro falharam');
}

async function handleLogout() {
  try {
    await chrome.storage.local.remove('auth');
    return { success: true };
  } catch (error) {
    console.error('[Background] Logout error:', error);
    throw error;
  }
}

async function checkLoginStatus() {
  try {
    await userManager.initialize();
    
    // Check both API auth and local UserManager
    const apiAuth = await chrome.storage.local.get('auth');
    const isApiLoggedIn = apiAuth.auth && apiAuth.auth.token;
    
    const isLocalLoggedIn = userManager.isUserLoggedIn();
    const userId = userManager.getCurrentUserId();
    const username = userManager.getCurrentUsername();
    
    console.log(`[Background] Verificação de status de login - API: ${isApiLoggedIn ? 'Sim' : 'Não'}, Local: ${isLocalLoggedIn ? `Sim (${userId})` : 'Não'}`);
    
    // Return true if either system shows logged in
    const isLoggedIn = isApiLoggedIn || isLocalLoggedIn;
    
    return {
      isLoggedIn: isLoggedIn,
      userId: userId,
      username: username,
      apiAuth: isApiLoggedIn,
      localAuth: isLocalLoggedIn
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
          timestamp: getCompatibleTimestamp(),
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

// ==================== FUNÇÃO PARA LIDAR COM CERTIFICADOS AUTO-ASSINADOS ====================
async function fetchWithSelfSignedCert(url, options = {}) {
  console.log("[Background] Tentando fetch com suporte a certificado auto-assinado:", url);
  
  try {
    // Para Chrome Extensions, podemos usar uma abordagem específica
    // que funciona com certificados auto-assinados
    
    const defaultOptions = {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'CPCT-Extension/1.0'
      },
      credentials: 'omit',
      cache: 'no-cache'
    };
    
    const finalOptions = { ...defaultOptions, ...options };
    
    console.log("[Background] Fazendo requisição com opções:", finalOptions);
    
    // Usar Promise.race para timeout manual
    const response = await Promise.race([
      fetch(url, finalOptions),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Request timeout')), 10000)
      )
    ]);
    
    console.log("[Background] Resposta recebida:", response.status, response.statusText);
    return response;
    
  } catch (error) {
    console.log("[Background] Erro no fetch:", error.message);
    
    // Se falhou, tentar com mode: 'no-cors' como último recurso
    if (error.message.includes('Failed to fetch') && !options.mode) {
      console.log("[Background] Tentando com mode: no-cors...");
      try {
        const noCorsResponse = await fetch(url, {
          ...options,
          mode: 'no-cors',
          method: options.method || 'GET'
        });
        console.log("[Background] Resposta no-cors recebida (opaque response)");
        return noCorsResponse;
      } catch (noCorsError) {
        console.log("[Background] Falha também com no-cors:", noCorsError.message);
        throw error; // Manter erro original
      }
    }
    
    throw error;
  }
}

// ==================== VERIFICAÇÃO DE API COM FALLBACK HTTP ====================
async function checkApiStatus() {
  console.log("[Background] 🔍 Iniciando verificação robusta da API...");
  console.log("[Background] 🎯 Endpoint HTTPS:", API_ENDPOINT);
  console.log("[Background] 🎯 Endpoint HTTP fallback:", API_ENDPOINT_HTTP_FALLBACK);
  
  const testResult = {
    isOnline: false,
    lastCheck: Date.now(),
    endpoint: API_ENDPOINT,
    error: null,
    healthData: null,
    certificateIssue: false,
    usingFallback: false
  };
  
  // Lista de endpoints para testar em ordem de prioridade
  const endpointsToTest = [
    { url: `${API_ENDPOINT}/health`, description: 'HTTPS Health', type: 'https' },
    { url: `${API_ENDPOINT_HTTP_FALLBACK}/health`, description: 'HTTP Health', type: 'http' },
    { url: `${API_ENDPOINT}/`, description: 'HTTPS Root', type: 'https' },
    { url: `${API_ENDPOINT_HTTP_FALLBACK}/`, description: 'HTTP Root', type: 'http' }
  ];
  
  for (const endpoint of endpointsToTest) {
    try {
      console.log(`[Background] 📡 Testando ${endpoint.description}: ${endpoint.url}`);
      
      const response = await Promise.race([
        fetch(endpoint.url, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': 'CPCT-Extension/1.0'
          },
          credentials: 'omit',
          cache: 'no-cache'
        }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Request timeout')), 8000)
        )
      ]);
      
      console.log(`[Background] ✅ ${endpoint.description} respondeu:`, response.status, response.statusText);
      
      if (response.ok) {
        try {
          const data = await response.json();
          console.log(`[Background] 📊 Health data de ${endpoint.description}:`, data);
          
          testResult.isOnline = true;
          testResult.healthData = data;
          testResult.endpoint = endpoint.url;
          testResult.usingFallback = endpoint.type === 'http';
          testResult.error = null;
          
          if (data.status === 'healthy') {
            console.log(`[Background] ✅ API saudável via ${endpoint.description}!`);
          } else {
            console.log(`[Background] ⚠️ API respondeu via ${endpoint.description} mas status: ${data.status}`);
            testResult.error = `Status: ${data.status}`;
          }
          
          break; // Sucesso! Parar de testar outros endpoints
          
        } catch (jsonError) {
          console.log(`[Background] ❌ JSON inválido de ${endpoint.description}:`, jsonError.message);
          // Mesmo assim, servidor está respondendo
          testResult.isOnline = true;
          testResult.healthData = { status: 'responding', note: 'JSON inválido' };
          testResult.endpoint = endpoint.url;
          testResult.usingFallback = endpoint.type === 'http';
          testResult.error = 'Resposta não é JSON válido';
          break; // Pelo menos temos resposta
        }
      } else {
        console.log(`[Background] ⚠️ ${endpoint.description} retornou HTTP ${response.status}`);
        // Servidor online mas com erro - ainda é um resultado válido
        testResult.isOnline = true;
        testResult.healthData = { status: 'error', httpStatus: response.status };
        testResult.endpoint = endpoint.url;
        testResult.usingFallback = endpoint.type === 'http';
        testResult.error = `HTTP ${response.status}`;
        break; // Servidor está online
      }
      
    } catch (error) {
      console.log(`[Background] ❌ ${endpoint.description} falhou:`, error.message);
      
      if (endpoint.type === 'https' && error.message.includes('Failed to fetch')) {
        testResult.certificateIssue = true;
        console.log(`[Background] 🔒 Problema de certificado detectado com ${endpoint.description}`);
      }
      
      // Continuar para próximo endpoint
      continue;
    }
  }
  
  // Se nenhum endpoint funcionou
  if (!testResult.isOnline) {
    console.log("[Background] 💀 Todos os endpoints falharam");
    testResult.error = 'Servidor completamente inacessível (HTTPS e HTTP)';
    testResult.healthData = { status: 'offline' };
  }
  
  // Guardar resultado global
  apiStatus = testResult;
  
  // Log final detalhado
  const statusEmoji = testResult.isOnline ? '✅' : '❌';
  const certEmoji = testResult.certificateIssue ? '🔒' : '';
  const fallbackEmoji = testResult.usingFallback ? '🔄' : '';
  
  console.log(`[Background] ${statusEmoji}${certEmoji}${fallbackEmoji} RESULTADO FINAL:`, {
    online: testResult.isOnline,
    endpoint: testResult.endpoint,
    usingFallback: testResult.usingFallback,
    certificateIssue: testResult.certificateIssue,
    error: testResult.error,
    healthData: testResult.healthData
  });
  
  // Notificar popup
  try {
    chrome.runtime.sendMessage({ 
      action: "apiStatusUpdate", 
      data: testResult 
    });
  } catch (msgError) {
    console.log("[Background] 📱 Popup não está aberto para notificação");
  }
  
  return testResult;
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

// ==================== INICIALIZAÇÃO DO SCRIPT ====================
initializeBackgroundScript();