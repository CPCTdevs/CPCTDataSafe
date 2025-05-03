// Adicione este código no início do arquivo background.js para verificar o contexto da extensão
function isExtensionContextValid() {
  try {
    // Tenta acessar uma API do chrome que falharia se o contexto fosse invalidado
    chrome.runtime.id;
    return true;
  } catch (e) {
    console.warn("Contexto da extensão de background invalidado");
    return false;
  }
}

// Classe UserManager para gerenciar usuários
class UserManager {
  constructor() {
    this.currentUser = null;
    this.isInitialized = false;
    this.initializationPromise = null;
  }

  async initialize() {
    if (!isExtensionContextValid()) return; // Verificar contexto
    // Se já estiver inicializado, retorna imediatamente
    if (this.isInitialized) return;
    
    // Se já estiver inicializando, retorna a promise existente
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    
    // Cria uma nova promise de inicialização
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
        resolve(); // Resolve mesmo com erro para não bloquear a aplicação
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
      // Verificar se o usuário já existe
      const result = await this.getStorageData(["users"]);
      const users = result.users || {};
      
      if (users[username]) {
        return { success: false, message: "Este nome de usuário já está em uso" };
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
      console.error("UserManager: Erro ao registrar usuário:", error);
      return { success: false, message: `Erro ao registrar usuário: ${error.message}` };
    }
  }

  async loginUser(username, password) {
    if (!isExtensionContextValid()) return { success: false, message: "Contexto inválido" };
    try {
      // Verificar credenciais
      const result = await this.getStorageData(["users"]);
      const users = result.users || {};
      
      if (users[username] && users[username].password === this.hashPassword(password)) {
        const userId = users[username].userId;
        const loginTime = new Date().toISOString();
        
        // Armazenar informações de login
        await this.setStorageData({
          userLoggedIn: true,
          userId: userId,
          username: username,
          lastLogin: loginTime
        });
        
        // Atualizar usuário atual
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
        lastLogin: null // Limpar lastLogin também
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
    // Combinar timestamp com string aleatória
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substring(2, 10);
    return `user_${timestamp}_${randomStr}`;
  }

  hashPassword(password) {
    // Esta é uma implementação simples para demonstração
    // Em produção, use uma biblioteca de hash segura como bcrypt ou Argon2
    // AVISO: NÃO USE ESTE HASH EM PRODUÇÃO REAL
    let hash = 0;
    if (!password || typeof password !== "string") return "";
    for (let i = 0; i < password.length; i++) {
      const char = password.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Converter para inteiro de 32 bits
    }
    return hash.toString(16); // Converter para string hexadecimal
  }
}

// Background script para a extensão CPCT Data Safe

// Configurações (considerar mover para config.js ou storage)
const API_ENDPOINT = "http://localhost:5000/data";
const API_KEY = "12345abcde";
const DATA_SEND_INTERVAL = 60000; // 1 minuto
const MAX_PENDING_DATA_COUNT = 100; // Enviar quando atingir este número
const CLEANUP_INTERVAL = 3600000; // 1 hora (limpar dados com mais de 24h)
const LOGIN_CHECK_INTERVAL = 300000; // 5 minutos
const DIAGNOSTIC_INTERVAL = 30000; // 30 segundos

// Variáveis globais
let lastUploadAttempt = null;
let lastUploadSuccess = false;
let apiStatus = { success: true, pingTime: null, lastCheck: null }; // Status da API (não implementado check)

// Armazenamento de dados coletados
let cpctData = {
  requests: [],
  userActions: [],
  pageViews: [], // Não utilizado atualmente?
  errors: [], // Captura erros da página via content script (pageError)
  headers: [], // Capturado via webRequest ou content script
  metadata: [], // Capturado via content script
  profiles: [], // Não utilizado atualmente?
  documentContents: [] // Capturado via content script
};

let lastDataSendTime = Date.now();
let pendingDataCount = 0;
let isInitialized = false;
let userManager = new UserManager();

// --- Inicialização ---

// Inicializar quando o background script carregar
initializeBackgroundScript();

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
    
    // Verificar se há dados pendentes para enviar (pode ter sido interrompido antes)
    // TODO: Carregar dados pendentes do storage? Por enquanto, apenas envia se pendingDataCount > 0
    if (pendingDataCount > 0) {
      console.log(`Dados pendentes (${pendingDataCount}) encontrados na inicialização. Tentando enviar...`);
      sendDataToServer();
    }
  } catch (error) {
    console.error("Erro fatal durante a inicialização do background script:", error);
    // Considerar notificar o usuário ou tentar reiniciar?
  }

  // Configurar listeners de mensagens e eventos
  setupListeners();

  // Configurar tarefas periódicas
  setupPeriodicTasks();
}

function setupListeners() {
    if (!isExtensionContextValid()) return;
    // Listener para mensagens do content script e popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!isExtensionContextValid()) {
            console.warn("Contexto inválido ao receber mensagem.");
            // Não podemos mais usar sendResponse aqui
            return false; // Indicar que a resposta não será enviada
        }
        
        // Log detalhado da mensagem recebida
        const senderInfo = sender.tab ? `tab ${sender.tab.id} (${sender.tab.url?.substring(0, 50)}...)` : (sender.id ? `ext ${sender.id}` : "desconhecido");
        console.log(`[Background] Mensagem recebida: ${message?.action} de ${senderInfo}`, message?.data ? ` | Tipo de dados: ${message.data.type}` : "");
        // Log completo do objeto de dados para depuração (pode ser verboso)
        // console.log("[Background] Dados recebidos:", JSON.stringify(message?.data));
        
        let isAsync = false;
        try {
            switch (message.action) {
                case "ping":
                    sendResponse({ status: "pong" });
                    break;
                case "userAction":
                    try {
                        // Log antes de chamar handleUserAction
                        console.log(`[Background] Processando userAction tipo: ${message?.data?.type}`);
                        const result = handleUserAction(message.data, sender.tab);
                        sendResponse(result); // Retorna { status: "received" } ou { status: "error", ... }
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
                    // Evitar enviar dados muito grandes para o popup
                    const previewData = {
                        requests: cpctData.requests.slice(-10), // Últimos 10
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
                        status: apiStatus // Status atual da API
                    });
                    break;
                case "forceUpload":
                    isAsync = true;
                    sendDataToServer(true) // Forçar envio
                        .then(result => {
                            if (isExtensionContextValid()) sendResponse(result);
                        })
                        .catch(error => {
                            console.error("[Background] Erro no forceUpload:", error);
                            // CORREÇÃO: Garantir que error.message exista ou fornecer um padrão
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
                // Tentar enviar resposta de erro apenas se não for assíncrono
                if (!isAsync && isExtensionContextValid()) {
                    sendResponse({ success: false, message: `Erro interno: ${error.message || "Erro desconhecido"}` });
                }
            } catch (e) {
                console.error("[Background] Erro ao enviar resposta de erro:", e);
            }
        }
        
        // Retornar true para indicar resposta assíncrona
        return isAsync;
    });

    // Listeners para webRequest (COMENTADOS - Captura principal via content script)
    /*
    chrome.webRequest.onBeforeSendHeaders.addListener(...);
    chrome.webRequest.onCompleted.addListener(...);
    chrome.webRequest.onErrorOccurred.addListener(...);
    */
}

function setupPeriodicTasks() {
    if (!isExtensionContextValid()) return;
    // Envio periódico de dados
    setInterval(() => {
        if (!isExtensionContextValid()) return;
        // Enviar se tiver dados pendentes E (passou o intervalo OU atingiu o limite)
        if (isInitialized && pendingDataCount > 0 && 
            (pendingDataCount >= MAX_PENDING_DATA_COUNT || Date.now() - lastDataSendTime > DATA_SEND_INTERVAL)) {
            console.log(`[Background] Disparando envio periódico (Count: ${pendingDataCount}, Time since last: ${Date.now() - lastDataSendTime}ms)`);
            sendDataToServer();
        }
    }, DATA_SEND_INTERVAL / 2); // Verificar mais frequentemente que o intervalo de envio

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
            // Re-inicializar/verificar UserManager periodicamente pode ajudar a sincronizar estado
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
}

// --- Manipulação de Dados ---

// Gerar ID de correlação para eventos
function generateCorrelationId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

// Processar ação do usuário recebida do content script ou webRequest
function handleUserAction(action, tab) {
  // Log detalhado da ação recebida para depuração
  console.log("[Background] handleUserAction - Recebido tipo:", action?.type, " | Dados:", JSON.stringify(action));
  
  // Verificações de segurança
  if (!action || typeof action !== "object" || !action.type) {
    console.warn("[Background] handleUserAction - Recebida ação inválida ou sem tipo:", action);
    return { status: "error", message: "Ação inválida ou sem tipo" };
  }

  // Adicionar informações do usuário (apenas se logado)
  const userId = userManager && userManager.isUserLoggedIn() ? userManager.getCurrentUserId() : null;
  if (userId) {
    action.userId = userId;
  } else {
      // console.log("[Background] handleUserAction - Ação recebida sem usuário logado:", action.type);
  }
  
  // Adicionar informações da aba (se vier de um content script)
  if (tab) {
    action.tabId = tab.id;
    // Não incluir URL/Title da aba aqui para evitar redundância (já está no pageContext da ação)
  }
  
  // Garantir timestamp
  if (!action.timestamp) {
    action.timestamp = new Date().toISOString();
  }
  
  // Armazenar a ação no array apropriado
  let dataStored = false;
  let storedIn = ""; // Para log

  // CORREÇÃO: Melhorar a classificação e adicionar logs
  if (action.type === "xhr" || action.type === "fetch" || 
      action.type === "xhrError" || action.type === "fetchError" ||
      action.type === "request" || action.type === "requestError") { // Incluindo tipos de webRequest
    cpctData.requests.push(action);
    storedIn = "requests";
    dataStored = true;
  } else if (action.type === "header") { // Tipo específico de webRequest
    cpctData.headers.push(action);
    storedIn = "headers";
    dataStored = true;
  } else if (action.type === "documentContent") {
    cpctData.documentContents.push(action);
    storedIn = "documentContents";
    dataStored = true;
  } else if (action.type === "pageMetadata") {
    cpctData.metadata.push(action);
    storedIn = "metadata";
    dataStored = true;
  } else if (action.type === "pageError" || action.type === "internalContentScriptError") { // Erros JS da página ou erros internos do content script
    cpctData.errors.push(action);
    storedIn = "errors";
    dataStored = true;
  } else if (action.type === "scriptInjected" || action.type === "contentScriptInitialized" || action.type === "diagnosticEvent") {
      // Ações de sistema/diagnóstico
      cpctData.userActions.push(action); // Armazenar em userActions por enquanto
      storedIn = "userActions (system)";
      dataStored = true;
  } else {
    // Todas as outras ações (click, keyInput, scroll, etc.)
    cpctData.userActions.push(action);
    storedIn = "userActions (interaction)";
    dataStored = true;
  }
  
  // Incrementar contador apenas se dados foram armazenados
  if (dataStored) {
      pendingDataCount++;
      console.log(`[Background] handleUserAction - Ação tipo '${action.type}' armazenada em '${storedIn}'. Pending: ${pendingDataCount}`);
  } else {
      console.warn(`[Background] handleUserAction - Ação tipo '${action.type}' não foi armazenada.`);
  }
  
  // Verificar se precisa enviar dados
  if (dataStored && isInitialized && 
      (pendingDataCount >= MAX_PENDING_DATA_COUNT || Date.now() - lastDataSendTime > DATA_SEND_INTERVAL)) {
    console.log(`[Background] Disparando envio por handleUserAction (Count: ${pendingDataCount}, Time since last: ${Date.now() - lastDataSendTime}ms)`);
    sendDataToServer();
  }
  
  return { status: "received" }; // Retornar resposta explícita
}

// Enviar dados para o servidor
async function sendDataToServer(forceUpload = false) {
  if (!isExtensionContextValid()) {
      console.warn("[Background] Contexto inválido ao tentar enviar dados.");
      return { success: false, message: "Contexto inválido" };
  }
  // Verificar se há dados para enviar
  if (pendingDataCount === 0 && !forceUpload) { // Permitir envio forçado mesmo sem dados (para teste)
    console.log("[Background] Nenhum dado pendente para enviar.");
    return { success: true, message: "Nenhum dado para enviar" };
  }
  
  // Garantir que o UserManager está inicializado
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
  
  // Verificar se o usuário está logado
  let effectiveUserId = userManager.getCurrentUserId();
  let effectiveUsername = userManager.getCurrentUsername();

  if (!effectiveUserId) {
    console.log("[Background] Usuário não está logado.");
    // Tentar verificar storage novamente como fallback
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
  
  // Atualizar timestamp da última tentativa
  lastUploadAttempt = new Date().toISOString();
  
  // Preparar dados para envio (criar cópias)
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
    // pageViews: [...cpctData.pageViews], // Adicionar se usado
    // profiles: [...cpctData.profiles], // Adicionar se usado
  };
  
  // Contar total de itens reais
  const totalItems = dataToSend.userActions.length + dataToSend.requests.length + 
                     dataToSend.errors.length + dataToSend.headers.length + 
                     dataToSend.metadata.length + dataToSend.documentContents.length; // Adicionar outros arrays se usados
  
  // Limpar dados locais *antes* do envio
  const dataSentSnapshot = { ...cpctData }; // Guardar snapshot para possível recuperação
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
  lastDataSendTime = Date.now(); // Atualizar tempo
  
  try {
    console.log(`[Background] Enviando ${totalItems} itens para API: ${API_ENDPOINT} (Usuário: ${effectiveUserId})`);
    
    // Enviar dados para o servidor
    const response = await fetch(API_ENDPOINT, {
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
    return { success: true, itemCount: totalItems };

  } catch (error) {
    console.error("[Background] Erro ao enviar dados:", error);
    
    // Rollback: Restaurar dados não enviados
    console.log("[Background] Restaurando dados não enviados...");
    cpctData.userActions = [...dataSentSnapshot.userActions, ...cpctData.userActions];
    cpctData.requests = [...dataSentSnapshot.requests, ...cpctData.requests];
    cpctData.pageViews = [...dataSentSnapshot.pageViews, ...cpctData.pageViews];
    cpctData.errors = [...dataSentSnapshot.errors, ...cpctData.errors];
    cpctData.headers = [...dataSentSnapshot.headers, ...cpctData.headers];
    cpctData.metadata = [...dataSentSnapshot.metadata, ...cpctData.metadata];
    cpctData.profiles = [...dataSentSnapshot.profiles, ...cpctData.profiles];
    cpctData.documentContents = [...dataSentSnapshot.documentContents, ...cpctData.documentContents];
    
    // Recalcular pendingDataCount
    pendingDataCount = cpctData.userActions.length + cpctData.requests.length + cpctData.errors.length + 
                       cpctData.headers.length + cpctData.metadata.length + cpctData.documentContents.length; // Adicionar outros
    console.log(`[Background] Dados restaurados. Contagem pendente: ${pendingDataCount}`);
    
    lastUploadSuccess = false;
    // CORREÇÃO: Garantir que error.message exista ou fornecer um padrão
    const errorMessage = error?.message || "Erro desconhecido durante o envio.";
    notifyPopup("uploadComplete", { success: false, timestamp: lastUploadAttempt, error: errorMessage });
    return { success: false, message: errorMessage };
  }
}

// Limpar dados antigos para evitar uso excessivo de memória
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
              return false; // Remover item com timestamp inválido
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
  
  // Atualizar contagem de dados pendentes após limpeza
  pendingDataCount = cpctData.userActions.length + cpctData.requests.length + cpctData.errors.length + 
                     cpctData.headers.length + cpctData.metadata.length + cpctData.documentContents.length; // Adicionar outros
  
  if (cleanedCount > 0) {
      console.log(`[Background] Limpeza concluída. ${cleanedCount} itens removidos. Contagem pendente: ${pendingDataCount} (antes: ${oldPendingCount})`);
  }
}

// --- Autenticação --- (Wrappers para UserManager)

async function handleLogin(username, password) {
  if (!userManager) return { success: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize(); // Garantir inicialização
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
    await userManager.initialize(); // Garantir inicialização
    return await userManager.registerUser(username, password);
  } catch (error) {
    console.error("[Background] Erro ao registrar usuário:", error);
    return { success: false, message: `Erro ao processar registro: ${error.message || "Erro desconhecido"}` };
  }
}

async function handleLogout() {
  if (!userManager) return { success: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize(); // Garantir inicialização
    return await userManager.logoutUser();
  } catch (error) {
    console.error("[Background] Erro ao fazer logout:", error);
    return { success: false, message: `Erro ao processar logout: ${error.message || "Erro desconhecido"}` };
  }
}

async function checkLoginStatus() {
  if (!userManager) return { isLoggedIn: false, message: "UserManager não inicializado" };
  try {
    await userManager.initialize(); // Garantir inicialização
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

// --- Diagnóstico e Utilitários ---

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
         errors: cpctData.errors.length,
         // Adicionar outros se usados
     }
   };

   console.log("[Background] Diagnóstico:", stats);
   
   // Verificar tipos de requisições pendentes
   if (cpctData.requests.length > 0) {
     const requestTypes = cpctData.requests.reduce((acc, req) => {
       const type = req.type || "unknown";
       acc[type] = (acc[type] || 0) + 1;
       return acc;
     }, {});
     console.log("[Background] Tipos de requisições pendentes:", requestTypes);
   }
   // Verificar tipos de erros pendentes
   if (cpctData.errors.length > 0) {
     const errorTypes = cpctData.errors.reduce((acc, err) => {
       const type = err.type || "unknownError";
       acc[type] = (acc[type] || 0) + 1;
       return acc;
     }, {});
     console.log("[Background] Tipos de erros pendentes:", errorTypes);
   }
}

// Função auxiliar para notificar o popup (se aberto)
function notifyPopup(action, data) {
    if (!isExtensionContextValid()) return;
    try {
        chrome.runtime.sendMessage({ action: action, data: data }, response => {
            if (chrome.runtime.lastError) {
                // Comum se o popup não estiver aberto
            } else {
                // console.log("[Background] Notificação enviada para popup:", action);
            }
        });
    } catch (error) {
        console.warn("[Background] Erro ao tentar notificar popup:", error);
    }
}

// Função de depuração para status de login
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

