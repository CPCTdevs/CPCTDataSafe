// ===================== CONFIGURAÇÃO =====================

const CONFIG = {
  GOOGLE_DOMAINS: ['google.com', 'youtube.com'],
  REQUEST_ASSOCIATION_TIME: 5000,
  CORRELATION_UPDATE_INTERVAL: 15000,
  MOUSE_MOVEMENT_INTERVAL: 5000,
  CLEANUP_INTERVAL: 30000,
  REQUEST_CHECK_INTERVAL: 60000,
  KEY_INPUT_DEBOUNCE: 1000,
  SCROLL_DEBOUNCE: 500,
  DOCUMENT_CONTENT_DEBOUNCE: 5000,
  METADATA_EXTRACTION_DELAY: 2000,
  DOCUMENT_CAPTURE_DELAY: 3000,
  INITIALIZATION_DELAY: 1000
};

// ===================== GERENCIAMENTO DE ESTADO =====================

class AppState {
  constructor() {
    this.eventCorrelationId = this.generateCorrelationId();
    this.backgroundCommunicationVerified = false;
    this.scriptInjectionAttempted = false;
    this.scriptInjectedSuccessfully = false;
    this.lastUserAction = null;
    this.pageLoadTime = performance.now();
    this.focusState = document.hasFocus();
    this.lastCorrelationUpdateTime = Date.now();
    this.lastDocumentContent = null;
    this.documentChangeBuffer = [];
    this.documentChangeTimer = null;
    this.pendingRequests = new Map();
    this.lastRequestTime = null;
    this.lastInteractionTime = null;
    this.lastMousePosition = { x: 0, y: 0 };
    this.mouseMoved = false;
    this.keyBuffer = "";
    this.keyTimer = null;
  }

  generateCorrelationId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  }
}

const state = new AppState();

// ===================== FUNÇÕES UTILITÁRIAS =====================

class Utils {
  static isExtensionContextValid() {
    try {
      chrome.runtime.id;
      return true;
    } catch (e) {
      console.warn("CPCT Data Safe: Contexto da extensão invalidado.");
      return false;
    }
  }

  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  static getSelector(element) {
    if (!element) return null;
    if (element.id) return `#${element.id}`;
    if (element.tagName === "BODY") return "BODY";

    let path = "";
    try {
      while (element && element.parentElement && element.tagName !== "BODY") {
        let siblingIndex = 1;
        let sibling = element.previousElementSibling;
        while (sibling) {
          if (sibling.tagName === element.tagName) {
            siblingIndex++;
          }
          sibling = sibling.previousElementSibling;
        }
        const tagName = element.tagName.toLowerCase();
        const nthChild = `:nth-of-type(${siblingIndex})`;
        path = ` > ${tagName}${nthChild}${path}`;
        element = element.parentElement;
      }
      return element && element.tagName === "BODY" ? `BODY${path}`.trim() : null;
    } catch (e) {
      console.warn("[CPCT Content Script] Erro ao gerar seletor:", e);
      return null;
    }
  }

  static getTargetInfo(element) {
    if (!element) return null;
    return {
      tagName: element.tagName,
      id: element.id || null,
      classes: element.classList ? Array.from(element.classList) : [],
      selector: this.getSelector(element),
      name: element.name || null,
      role: element.getAttribute("role") || null,
      ariaLabel: element.getAttribute("aria-label") || null,
      text: element.innerText ? element.innerText.substring(0, 100) : null
    };
  }

  static getLocationInfo() {
    try {
      const url = new URL(window.location.href);
      return {
        protocol: url.protocol,
        hostname: url.hostname,
        pathname: url.pathname,
        search: url.search,
        hash: url.hash
      };
    } catch (e) {
      return { raw: window.location.href };
    }
  }

  static isSensitiveField(element) {
    return element.type === "password" || 
           element.name?.toLowerCase().includes("password");
  }
}

// ===================== IDENTIFICAÇÃO DE SERVIÇO =====================

class ServiceIdentifier {
  static identifyGoogleService() {
    const host = window.location.hostname;
    const path = window.location.pathname;

    const services = {
      'mail.google.com': 'Gmail',
      'drive.google.com': 'Google Drive',
      'docs.google.com': 'Google Docs',
      'sheets.google.com': 'Google Sheets',
      'slides.google.com': 'Google Slides',
      'calendar.google.com': 'Google Calendar',
      'meet.google.com': 'Google Meet',
      'photos.google.com': 'Google Photos',
      'contacts.google.com': 'Google Contacts',
      'keep.google.com': 'Google Keep',
      'youtube.com': 'YouTube'
    };

    for (const [domain, service] of Object.entries(services)) {
      if (host.includes(domain)) return service;
    }

    if (host.includes('google.com')) {
      if (path.includes('/maps')) return 'Google Maps';
      if (path === '/' || path.startsWith('/search') || path.startsWith('/webhp')) {
        return 'Google Search';
      }
    }

    return 'Other Google Service';
  }

  static identifyCurrentView() {
    const url = window.location.href;
    const path = window.location.pathname;
    const hash = window.location.hash;

    // Visões do Gmail
    if (url.includes('mail.google.com')) {
      const views = {
        '#inbox': 'Inbox',
        '#sent': 'Sent',
        '#drafts': 'Drafts'
      };
      
      for (const [hashPattern, view] of Object.entries(views)) {
        if (hash.startsWith(hashPattern)) return view;
      }
      
      if (hash.match(/#label\/[^\/]+/)) return 'Label View';
      if (hash.match(/#search\/.+/)) return 'Search Results';
      if (hash.match(/#[^\/]+\/[^\/]+/)) return 'Email Read View';
      return 'Gmail - Other';
    }

    // Visões do Drive
    if (url.includes('drive.google.com')) {
      const views = {
        '/drive/my-drive': 'My Drive',
        '/drive/shared-with-me': 'Shared with me',
        '/drive/recent': 'Recent',
        '/drive/starred': 'Starred',
        '/drive/trash': 'Trash',
        '/drive/folders/': 'Folder View',
        '/drive/search': 'Search Results'
      };
      
      for (const [pathPattern, view] of Object.entries(views)) {
        if (url.includes(pathPattern)) return view;
      }
      return 'Drive - Other';
    }

    // Editores de documentos
    if (url.includes('docs.google.com') || 
        url.includes('sheets.google.com') || 
        url.includes('slides.google.com')) {
      if (path.includes('/edit')) return 'Edit Mode';
      if (path.includes('/view') || path.includes('/preview')) return 'View Mode';
      if (path.includes('/copy')) return 'Copy Document';
      if (path.match(/\/d\/[^\/]+\/?$/) || path.match(/\/d\/[^\/]+\/$/)) return 'Edit Mode';
      return 'Document/Sheet/Slide - Other';
    }

    // Visões do Calendário
    if (url.includes('calendar.google.com')) {
      const views = {
        '/day': 'Day View',
        '/week': 'Week View',
        '/month': 'Month View',
        '/year': 'Year View',
        '/agenda': 'Agenda View',
        '/eventedit': 'Event Edit'
      };
      
      for (const [pathPattern, view] of Object.entries(views)) {
        if (url.includes(pathPattern)) return view;
      }
      return 'Calendar - Other';
    }

    // Visões de busca
    if (url.includes('google.com/search') || url.includes('google.com/webhp')) {
      const params = new URLSearchParams(window.location.search);
      const searchTypes = {
        'isch': 'Image Search',
        'vid': 'Video Search',
        'nws': 'News Search',
        'shop': 'Shopping Search'
      };
      
      const tbm = params.get('tbm');
      return searchTypes[tbm] || 'Web Search Results';
    }

    return 'Default View';
  }
}

// ===================== COMUNICAÇÃO =====================

class Communication {
  static sendMessage(message, callback) {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          console.error(`[CPCT Content Script] Erro ao enviar mensagem:`, chrome.runtime.lastError.message);
        } else if (callback) {
          callback(response);
        }
      });
    } catch (error) {
      console.error(`[CPCT Content Script] Erro em sendMessage:`, error);
    }
  }

  static async verifyBackgroundCommunication() {
    if (!Utils.isExtensionContextValid()) return;
    
    console.log("[CPCT Content Script] Pingando script de background...");
    try {
      this.sendMessage({ action: "ping" }, (response) => {
        if (chrome.runtime.lastError) {
          console.error("[CPCT Content Script] Ping falhou:", chrome.runtime.lastError.message);
          state.backgroundCommunicationVerified = false;
        } else if (response && response.status === "pong") {
          console.log("[CPCT Content Script] Ping bem sucedido!");
          state.backgroundCommunicationVerified = true;
        } else {
          console.warn("[CPCT Content Script] Ping recebeu resposta inesperada:", response);
          state.backgroundCommunicationVerified = false;
        }
      });
    } catch (error) {
      console.error("[CPCT Content Script] Erro ao enviar ping:", error);
      state.backgroundCommunicationVerified = false;
    }
  }

  static refreshCorrelationId() {
    if (!Utils.isExtensionContextValid()) return;

    try {
      this.sendMessage({ action: "getCorrelationId" }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn("[CPCT Content Script] Erro ao obter ID de correlação:", chrome.runtime.lastError.message);
          state.eventCorrelationId = state.generateCorrelationId();
        } else if (response && response.correlationId) {
          state.eventCorrelationId = response.correlationId;
        } else {
          console.warn("[CPCT Content Script] Resposta inválida para ID de correlação.");
          state.eventCorrelationId = state.generateCorrelationId();
        }
        state.lastCorrelationUpdateTime = Date.now();
      });
    } catch (error) {
      console.error("[CPCT Content Script] Erro ao requisitar ID de correlação:", error);
      state.eventCorrelationId = state.generateCorrelationId();
      state.lastCorrelationUpdateTime = Date.now();
    }
  }
}

// ===================== RASTREAMENTO DE AÇÕES =====================

class ActionTracker {
  static sendUserActionWithCorrelation(action) {
    if (!Utils.isExtensionContextValid()) {
      console.warn("[CPCT Content Script] Tentando enviar ação com contexto inválido:", action.type);
      return;
    }

    try {
      if (Date.now() - state.lastCorrelationUpdateTime > CONFIG.CORRELATION_UPDATE_INTERVAL) {
        Communication.refreshCorrelationId();
      }

      state.lastInteractionTime = Date.now();

      const enrichedAction = {
        ...action,
        correlationId: state.eventCorrelationId,
        preciseTimestamp: performance.now(),
        timeFromPageLoad: performance.now() - state.pageLoadTime,
        pageContext: {
          title: document.title,
          url: window.location.href,
          referrer: document.referrer,
          viewport: {
            width: window.innerWidth,
            height: window.innerHeight
          },
          userAgent: navigator.userAgent,
          devicePixelRatio: window.devicePixelRatio || 1,
          language: navigator.language,
          hasFocus: state.focusState,
          locationInfo: Utils.getLocationInfo(),
          service: ServiceIdentifier.identifyGoogleService(),
          view: ServiceIdentifier.identifyCurrentView()
        }
      };

      if (action.type !== "mouseMovement" && action.type !== "scroll") {
        state.lastUserAction = {
          type: action.type,
          timestamp: action.timestamp,
          preciseTimestamp: enrichedAction.preciseTimestamp,
          target: action.target,
          value: action.value
        };
        console.log(`[CPCT Content Script] Atualizado lastUserAction: ${state.lastUserAction.type}`);
      }

      try {
        if (performance && performance.memory) {
          enrichedAction.performanceData = {
            memory: {
              usedJSHeapSize: performance.memory.usedJSHeapSize,
              totalJSHeapSize: performance.memory.totalJSHeapSize
            }
          };
        }
      } catch (e) {}

      console.log(`[CPCT Content Script] Enviando ação do usuário: ${action.type}`);
      Communication.sendMessage({ action: "userAction", data: enrichedAction });

    } catch (error) {
      console.error("[CPCT Content Script] Erro em sendUserActionWithCorrelation:", error, action);
      this.reportInternalError(error, "sendUserActionWithCorrelation", action);
    }
  }

  static reportInternalError(error, context, failedAction) {
    try {
      if (Utils.isExtensionContextValid()) {
        Communication.sendMessage({
          action: "userAction",
          data: {
            type: "internalContentScriptError",
            message: error.message,
            stack: error.stack,
            context: context,
            failedActionType: failedAction ? failedAction.type : "unknown",
            timestamp: new Date().toISOString()
          }
        });
      }
    } catch (sendError) {
      console.error("[CPCT Content Script] Falha ao enviar relatório de erro interno:", sendError);
    }
  }
}

// ===================== MANIPULADORES DE EVENTOS =====================

class EventHandlers {
  static setupEventListeners() {
    console.log("[CPCT Content Script] Configurando listeners de eventos...");

    // Eventos de clique
    document.addEventListener("click", (event) => {
      ActionTracker.sendUserActionWithCorrelation({
        type: "click",
        target: Utils.getTargetInfo(event.target),
        timestamp: new Date().toISOString(),
        position: { x: event.clientX, y: event.clientY }
      });
    }, true);

    // Eventos de teclado
    document.addEventListener("keydown", (event) => {
      if (["Control", "Shift", "Alt", "Meta"].includes(event.key)) return;

      const targetInfo = Utils.getTargetInfo(event.target);
      let valueToLog = event.key;

      if (Utils.isSensitiveField(event.target)) {
        valueToLog = "***";
      }

      clearTimeout(state.keyTimer);
      state.keyBuffer += valueToLog;
      
      state.keyTimer = setTimeout(() => {
        if (state.keyBuffer) {
          ActionTracker.sendUserActionWithCorrelation({
            type: "keyInput",
            target: targetInfo,
            value: state.keyBuffer,
            timestamp: new Date().toISOString()
          });
          state.keyBuffer = "";
        }
      }, CONFIG.KEY_INPUT_DEBOUNCE);

      if (event.key === "Enter" || event.key === "Tab") {
        clearTimeout(state.keyTimer);
        if (state.keyBuffer) {
          ActionTracker.sendUserActionWithCorrelation({
            type: "keyInput",
            target: targetInfo,
            value: state.keyBuffer,
            timestamp: new Date().toISOString()
          });
          state.keyBuffer = "";
        }
        ActionTracker.sendUserActionWithCorrelation({
          type: "keyDownSpecific",
          target: targetInfo,
          key: event.key,
          code: event.code,
          timestamp: new Date().toISOString()
        });
      }
    }, true);

    // Eventos de foco
    window.addEventListener("focus", () => {
      state.focusState = true;
      ActionTracker.sendUserActionWithCorrelation({
        type: "windowFocus",
        timestamp: new Date().toISOString()
      });
    }, true);

    window.addEventListener("blur", () => {
      state.focusState = false;
      ActionTracker.sendUserActionWithCorrelation({
        type: "windowBlur",
        timestamp: new Date().toISOString()
      });
    }, true);

    // Eventos de scroll
    let scrollTimer = null;
    document.addEventListener("scroll", () => {
      clearTimeout(scrollTimer);
      scrollTimer = setTimeout(() => {
        ActionTracker.sendUserActionWithCorrelation({
          type: "scroll",
          scrollPosition: { x: window.scrollX, y: window.scrollY },
          timestamp: new Date().toISOString()
        });
      }, CONFIG.SCROLL_DEBOUNCE);
    }, true);

    // Eventos de mudança
    document.addEventListener("change", (event) => {
      const targetInfo = Utils.getTargetInfo(event.target);
      let value = event.target.value;
      
      if (Utils.isSensitiveField(event.target)) {
        value = "***";
      }
      
      ActionTracker.sendUserActionWithCorrelation({
        type: "change",
        target: targetInfo,
        value: value,
        timestamp: new Date().toISOString()
      });
    }, true);

    // Eventos de erro
    window.addEventListener("error", (event) => {
      ActionTracker.sendUserActionWithCorrelation({
        type: "pageError",
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        error: event.error ? { 
          message: event.error.message, 
          stack: event.error.stack 
        } : null,
        timestamp: new Date().toISOString()
      });
    });

    window.addEventListener("unhandledrejection", (event) => {
      ActionTracker.sendUserActionWithCorrelation({
        type: "pageError",
        message: "Rejeição de promise não tratada",
        reason: event.reason ? String(event.reason) : null,
        timestamp: new Date().toISOString()
      });
    });

    // Movimento do mouse
    document.addEventListener("mousemove", (event) => {
      state.lastMousePosition = { x: event.clientX, y: event.clientY };
      state.mouseMoved = true;
    }, { capture: true, passive: true });

    console.log("[CPCT Content Script] Listeners de eventos configurados.");
  }

  static setupMessageListener() {
    window.addEventListener("message", event => {
      if (event.source !== window || !event.data || !event.data.__CPCT__) {
        return;
      }

      const msg = event.data;
      console.log(`[CPCT Content Script] Mensagem recebida do script injetado. Tipo: ${msg.type}`, JSON.stringify(msg));

      if (msg.type === "scriptInjected") {
        state.scriptInjectedSuccessfully = true;
        console.log("[CPCT Content Script] Confirmado que script interceptor está rodando via mensagem.");
        Communication.verifyBackgroundCommunication();
        return;
      }

      // Associar requisições com ações recentes do usuário
      if (msg.type === "xhr" || msg.type === "fetch" || msg.type === "xhrError" || msg.type === "fetchError") {
        console.log(`[CPCT Content Script] Verificando associação para requisição: ${msg.requestId}`);
        
        if (state.lastUserAction && 
            (performance.now() - state.lastUserAction.preciseTimestamp) < CONFIG.REQUEST_ASSOCIATION_TIME) {
          console.log(`[CPCT Content Script] Associando requisição ${msg.requestId} com última ação: ${state.lastUserAction.type}`);
          msg.associatedUserAction = {
            type: state.lastUserAction.type,
            timestamp: state.lastUserAction.timestamp,
            target: state.lastUserAction.target,
            value: state.lastUserAction.value
          };
        } else {
          console.log(`[CPCT Content Script] Nenhuma ação recente encontrada para associação com requisição ${msg.requestId}`);
        }
      }

      try {
        if (Utils.isExtensionContextValid()) {
          console.log(`[CPCT Content Script] Encaminhando mensagem tipo ${msg.type} para script de background...`);
          Communication.sendMessage({ action: "userAction", data: msg });

          if (msg.type === "xhr" || msg.type === "fetch") {
            state.lastRequestTime = Date.now();
          }
        } else {
          console.warn(`[CPCT Content Script] Contexto da extensão inválido, mensagem tipo ${msg.type} não encaminhada.`);
        }
      } catch (error) {
        console.error(`[CPCT Content Script] Erro ao encaminhar mensagem tipo ${msg.type} para background:`, error);
      }
    });
  }
}

// ===================== INJEÇÃO DE SCRIPT =====================

class ScriptInjector {
  static injectInterceptorFile() {
    console.log("[CPCT Content Script] Tentando injetar script interceptor do arquivo...");
    state.scriptInjectionAttempted = true;
    
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("interceptor.js");
      
      script.onload = function() {
        console.log("[CPCT Content Script] Script interceptor carregado com sucesso (evento onload).");
        this.remove();
      };
      
      script.onerror = function(e) {
        console.error("[CPCT Content Script] Falha ao carregar script interceptor do arquivo.", e);
        if (Utils.isExtensionContextValid()) {
          ActionTracker.sendUserActionWithCorrelation({
            type: "diagnosticEvent",
            event: "scriptInjectionFailed",
            method: "fileLoad",
            error: e ? (e.message || "Erro de carregamento desconhecido") : "Erro de carregamento desconhecido",
            timestamp: new Date().toISOString()
          });
        }
      };
      
      (document.head || document.documentElement).appendChild(script);
    } catch (error) {
      console.error("[CPCT Content Script] Erro ao criar ou anexar elemento de script interceptor:", error);
      if (Utils.isExtensionContextValid()) {
        ActionTracker.sendUserActionWithCorrelation({
          type: "diagnosticEvent",
          event: "scriptInjectionFailed",
          method: "fileLoadSetup",
          error: error ? error.message : "Erro de configuração desconhecido",
          timestamp: new Date().toISOString()
        });
      }
    }
  }
}

// ===================== MONITORAMENTO =====================

class Monitor {
  static extractPageMetadata() {
    if (!Utils.isExtensionContextValid()) return;
    console.log("[CPCT Content Script] Extraindo metadados da página...");
    
    const metadata = {
      title: document.title,
      url: window.location.href,
      referrer: document.referrer,
      charset: document.characterSet,
      contentType: document.contentType,
      language: document.documentElement.lang || navigator.language,
      metaTags: Array.from(document.querySelectorAll("meta"))
        .map(tag => ({ name: tag.name, content: tag.content })),
      linkTags: Array.from(document.querySelectorAll("link"))
        .map(tag => ({ rel: tag.rel, href: tag.href })),
      scripts: Array.from(document.querySelectorAll("script"))
        .map(tag => ({ src: tag.src })),
      service: ServiceIdentifier.identifyGoogleService(),
      view: ServiceIdentifier.identifyCurrentView()
    };
    
    ActionTracker.sendUserActionWithCorrelation({
      type: "pageMetadata",
      data: metadata,
      timestamp: new Date().toISOString()
    });
  }

  static sendMouseMovementData() {
    if (state.mouseMoved && Utils.isExtensionContextValid()) {
      ActionTracker.sendUserActionWithCorrelation({
        type: "mouseMovement",
        position: state.lastMousePosition,
        timestamp: new Date().toISOString()
      });
      state.mouseMoved = false;
    }
  }

  static observeDOMChanges() {
    if (!Utils.isExtensionContextValid()) return;
    console.log("[CPCT Content Script] Configurando observador de DOM...");
    
    const observer = new MutationObserver((mutations) => {
      // Lógica de manipulação de mutações pode ser adicionada aqui
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false
    });
    
    console.log("[CPCT Content Script] Observador de DOM ativo.");
  }

  static setupDocumentContentCapture() {
    if (!Utils.isExtensionContextValid()) return;
    console.log("[CPCT Content Script] Configurando captura de conteúdo do documento...");
    
    const editorElement = document.querySelector("textarea.docs-texteventtarget-iframe") || document.body;

    if (editorElement) {
      const debouncedSendContent = Utils.debounce(() => {
        if (state.documentChangeBuffer.length > 0 && Utils.isExtensionContextValid()) {
          ActionTracker.sendUserActionWithCorrelation({
            type: "documentContent",
            documentId: window.location.pathname,
            changes: state.documentChangeBuffer,
            timestamp: new Date().toISOString()
          });
          state.documentChangeBuffer = [];
        }
      }, CONFIG.DOCUMENT_CONTENT_DEBOUNCE);

      editorElement.addEventListener("input", (event) => {
        state.documentChangeBuffer.push({
          type: "input",
          timestamp: new Date().toISOString()
        });
        debouncedSendContent();
      });

      console.log("[CPCT Content Script] Captura de conteúdo do documento ativa.");
    } else {
      console.warn("[CPCT Content Script] Elemento editor não encontrado para captura de conteúdo.");
    }
  }

  static checkRequestDataCollection() {
    if (!Utils.isExtensionContextValid()) return;
    
    if (!state.lastRequestTime || Date.now() - state.lastRequestTime > CONFIG.REQUEST_CHECK_INTERVAL) {
      console.warn("[CPCT Content Script] Nenhuma requisição (XHR/Fetch) detectada no último minuto.");

      Communication.verifyBackgroundCommunication();

      if (state.scriptInjectionAttempted && !state.scriptInjectedSuccessfully) {
        console.log("[CPCT Content Script] Retentando injeção do script interceptor...");
        ScriptInjector.injectInterceptorFile();
      }

      ActionTracker.sendUserActionWithCorrelation({
        type: "diagnosticEvent",
        event: "noRequestsDetected",
        details: `Último horário de requisição: ${state.lastRequestTime ? new Date(state.lastRequestTime).toISOString() : "Nunca"}`,
        timestamp: new Date().toISOString()
      });
    }
  }
}

// ===================== INICIALIZAÇÃO =====================

class App {
  static initialize() {
    if (!Utils.isExtensionContextValid()) {
      console.error("[CPCT Content Script] Contexto inválido na inicialização. Abortando.");
      return;
    }

    // Verifica se estamos em um domínio alvo
    const hostname = window.location.hostname;
    const isTargetDomain = CONFIG.GOOGLE_DOMAINS.some(domain => 
      hostname.endsWith(domain)
    );

    if (!isTargetDomain) {
      console.log("CPCT Data Safe: Não é um domínio alvo. Script inativo.");
      return;
    }

    console.log("CPCT Data Safe: Content script inicializando em", hostname);

    // Configuração inicial
    Communication.verifyBackgroundCommunication();
    state.pageLoadTime = performance.now();
    state.focusState = document.hasFocus();

    // Injeta script interceptor
    ScriptInjector.injectInterceptorFile();

    // Configura listeners de eventos
    EventHandlers.setupEventListeners();
    EventHandlers.setupMessageListener();

    // Agenda evento de inicialização
    setTimeout(() => {
      try {
        if (Utils.isExtensionContextValid()) {
          ActionTracker.sendUserActionWithCorrelation({
            type: "contentScriptInitialized",
            timestamp: new Date().toISOString()
          });
        }
      } catch (e) {
        console.error("[CPCT Content Script] Erro ao enviar evento de inicialização:", e);
      }
    }, CONFIG.INITIALIZATION_DELAY);

    // Agenda extração de metadados
    setTimeout(() => Monitor.extractPageMetadata(), CONFIG.METADATA_EXTRACTION_DELAY);

    // Configura intervalos
    this.setupIntervals();

    // Configura recursos específicos de documento
    this.setupDocumentFeatures();

    // Inicia observação do DOM
    Monitor.observeDOMChanges();

    console.log("CPCT Data Safe: Inicialização do content script completa.");
  }

  static setupIntervals() {
    // Atualização do ID de correlação
    setInterval(() => {
      if (!Utils.isExtensionContextValid()) return;
      Communication.refreshCorrelationId();
    }, CONFIG.CORRELATION_UPDATE_INTERVAL);

    // Relatório de movimento do mouse
    setInterval(() => {
      if (!Utils.isExtensionContextValid()) return;
      try { Monitor.sendMouseMovementData(); } 
      catch (e) { console.error("Erro ao enviar movimento do mouse:", e); }
    }, CONFIG.MOUSE_MOVEMENT_INTERVAL);

    // Intervalo de limpeza
    setInterval(() => {
      if (!Utils.isExtensionContextValid()) return;
      // Lógica de limpeza pode ser adicionada aqui
    }, CONFIG.CLEANUP_INTERVAL);

    // Monitoramento de requisições
    setInterval(() => {
      if (!Utils.isExtensionContextValid()) return;
      try { Monitor.checkRequestDataCollection(); } 
      catch (e) { console.error("Erro ao verificar coleta de requisições:", e); }
    }, CONFIG.REQUEST_CHECK_INTERVAL);
  }

  static setupDocumentFeatures() {
    const hostname = window.location.hostname;
    const documentEditors = ['docs.google.com', 'sheets.google.com', 'slides.google.com'];
    
    if (documentEditors.some(editor => hostname.includes(editor))) {
      setTimeout(() => {
        try {
          Monitor.setupDocumentContentCapture();
        } catch (e) {
          console.error("Erro ao agendar captura de conteúdo do documento:", e);
        }
      }, CONFIG.DOCUMENT_CAPTURE_DELAY);
    }
  }
}

// Inicia a aplicação
App.initialize();