let eventCorrelationId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
let backgroundCommunicationVerified = false;
let scriptInjectionAttempted = false;
let scriptInjectedSuccessfully = false;

function isExtensionContextValid() {
  try {
    chrome.runtime.id;
    return true;
  } catch (e) {
    console.warn("CPCT Data Safe: Extension context invalidated.");
    return false;
  }
}

let lastUserAction = null; 
let pageLoadTime = performance.now();
let focusState = document.hasFocus();
let lastCorrelationUpdateTime = Date.now();

// Rastreamento de conteúdo do documento
let lastDocumentContent = null;

let documentChangeBuffer = [];
let documentChangeTimer = null;

// Rastreamento de requisições
let pendingRequests = new Map(); // Mapa de requestId -> info da requisição
let lastRequestTime = null;
let lastInteractionTime = null;
const MAX_REQUEST_ASSOCIATION_TIME = 5000; // Tempo máximo para associar interação com requisição (ms)


initialize();


function injectInterceptorFile() {
  console.log("[CPCT Content Script] Attempting to inject interceptor script from file...");
  scriptInjectionAttempted = true;
  try {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("interceptor.js");
    script.onload = function() {
      console.log("[CPCT Content Script] Interceptor script loaded successfully (onload event).");
      this.remove();
    };
    script.onerror = function(e) {
      console.error("[CPCT Content Script] Failed to load interceptor script from file.", e);
      if (isExtensionContextValid()) {
          sendUserActionWithCorrelation({
              type: "diagnosticEvent",
              event: "scriptInjectionFailed",
              method: "fileLoad",
              error: e ? (e.message || "Unknown load error") : "Unknown load error",
              timestamp: new Date().toISOString()
          });
      }
    };
    (document.head || document.documentElement).appendChild(script);
  } catch (error) {
      console.error("[CPCT Content Script] Error creating or appending interceptor script element:", error);
      if (isExtensionContextValid()) {
          sendUserActionWithCorrelation({
              type: "diagnosticEvent",
              event: "scriptInjectionFailed",
              method: "fileLoadSetup",
              error: error ? error.message : "Unknown setup error",
              timestamp: new Date().toISOString()
          });
      }
  }
}

injectInterceptorFile();

window.addEventListener("message", event => {
  if (event.source !== window || !event.data || !event.data.__CPCT__) {
    return;
  }

  const msg = event.data;
  console.log(`[CPCT Content Script] Received message from injected script. Type: ${msg.type}`, JSON.stringify(msg));

  if (msg.type === "scriptInjected") {
    scriptInjectedSuccessfully = true;
    console.log("[CPCT Content Script] Confirmed interceptor script is running via message.");
    verifyBackgroundCommunication();
    return;
  }
  // Associação
  if (msg.type === "xhr" || msg.type === "fetch" || msg.type === "xhrError" || msg.type === "fetchError") {
      console.log(`[CPCT Content Script] Checking for association for request: ${msg.requestId}`);
      if (lastUserAction && (performance.now() - lastUserAction.preciseTimestamp) < MAX_REQUEST_ASSOCIATION_TIME) {
          console.log(`[CPCT Content Script] Associating request ${msg.requestId} with last action: ${lastUserAction.type} (Timestamp diff: ${performance.now() - lastUserAction.preciseTimestamp}ms)`);
          msg.associatedUserAction = {
              type: lastUserAction.type,
              timestamp: lastUserAction.timestamp,
              target: lastUserAction.target,
              value: lastUserAction.value
          };
      } else {
          console.log(`[CPCT Content Script] No recent user action found for association with request ${msg.requestId}. Last action: ${lastUserAction ? lastUserAction.type + ' at ' + lastUserAction.timestamp : 'None'}`);
      }
  }
  
  try {
    if (isExtensionContextValid()) {
      console.log(`[CPCT Content Script] Forwarding message type ${msg.type} to background script...`);
      chrome.runtime.sendMessage({
        action: "userAction",
        data: msg
      }, function(response) { 
        if (chrome.runtime.lastError) {
          console.error(`[CPCT Content Script] Error sending message type ${msg.type} to background:`, chrome.runtime.lastError.message);
        } else if (response) {
          console.log(`[CPCT Content Script] Response from background for message type ${msg.type}:`, response);
        }
      });

      if (msg.type === "xhr" || msg.type === "fetch") {
        lastRequestTime = Date.now();
      }
    } else {
       console.warn(`[CPCT Content Script] Extension context invalid, message type ${msg.type} not forwarded.`);
    }
  } catch (error) {
    console.error(`[CPCT Content Script] Error forwarding message type ${msg.type} to background:`, error);
  }
});

function verifyBackgroundCommunication() {
  if (!isExtensionContextValid()) return;
  console.log("[CPCT Content Script] Pinging background script...");
  try {
      chrome.runtime.sendMessage({ action: "ping" }, function(response) {
          if (chrome.runtime.lastError) {
              console.error("[CPCT Content Script] Ping failed:", chrome.runtime.lastError.message);
              backgroundCommunicationVerified = false;
          } else if (response && response.status === "pong") {
              console.log("[CPCT Content Script] Ping successful!");
              backgroundCommunicationVerified = true;
          } else {
              console.warn("[CPCT Content Script] Ping received unexpected response:", response);
              backgroundCommunicationVerified = false;
          }
      });
  } catch (error) {
      console.error("[CPCT Content Script] Error sending ping:", error);
      backgroundCommunicationVerified = false;
  }
}

function refreshCorrelationId() {
  if (!isExtensionContextValid()) return;

  try {
    chrome.runtime.sendMessage({
      action: "getCorrelationId"
    }, function(response) {
      if (chrome.runtime.lastError) {
        console.warn("[CPCT Content Script] Error getting correlation ID:", chrome.runtime.lastError.message);
        eventCorrelationId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
        lastCorrelationUpdateTime = Date.now();
        return;
      }

      if (response && response.correlationId) {
        eventCorrelationId = response.correlationId;
        lastCorrelationUpdateTime = Date.now();
      } else {
        console.warn("[CPCT Content Script] Invalid response for correlation ID.");
        eventCorrelationId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
        lastCorrelationUpdateTime = Date.now();
      }
    });
  } catch (error) {
    console.error("[CPCT Content Script] Error requesting correlation ID:", error);
    eventCorrelationId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
    lastCorrelationUpdateTime = Date.now();
  }
}

// Atualizar o ID de correlação periodicamente
const correlationInterval = setInterval(() => {
    if (!isExtensionContextValid()) {
        clearInterval(correlationInterval);
        return;
    }
    refreshCorrelationId();
}, 15000);

// Função para enviar ações do usuário (clicks, keys, etc.) para o background
function sendUserActionWithCorrelation(action) {
  if (!isExtensionContextValid()) {
    console.warn("[CPCT Content Script] Attempting to send action with invalid context:", action.type);
    return;
  }

  try {
    if (Date.now() - lastCorrelationUpdateTime > 15000) {
      refreshCorrelationId();
    }

    lastInteractionTime = Date.now();

    action.correlationId = eventCorrelationId;
    action.preciseTimestamp = performance.now();
    action.timeFromPageLoad = action.preciseTimestamp - pageLoadTime;
    action.pageContext = {
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
      hasFocus: focusState,
      locationInfo: getLocationInfo(),
      service: identifyGoogleService(),
      view: identifyCurrentView()
    };

    if (action.type !== "mouseMovement" && action.type !== "scroll") {
        lastUserAction = {
            type: action.type,
            timestamp: action.timestamp,
            preciseTimestamp: action.preciseTimestamp,
            target: action.target ? {
                tagName: action.target.tagName,
                id: action.target.id,
                classes: action.target.classes,
                selector: action.target.selector
            } : null,
            value: action.value
        };
        console.log(`[CPCT Content Script] Updated lastUserAction: ${lastUserAction.type}`);
    }

    try {
      if (performance && performance.memory) {
        action.performanceData = {
          memory: {
            usedJSHeapSize: performance.memory.usedJSHeapSize,
            totalJSHeapSize: performance.memory.totalJSHeapSize
          }
        };
      }
    } catch (e) { }

    console.log(`[CPCT Content Script] Sending user action: ${action.type}`);

    chrome.runtime.sendMessage({
      action: "userAction",
      data: action
    }, function(response) {
      if (chrome.runtime.lastError) {
        console.warn(`[CPCT Content Script] Error sending userAction type ${action.type}:`, chrome.runtime.lastError.message);
      }
    });

  } catch (error) {
    console.error("[CPCT Content Script] Error in sendUserActionWithCorrelation:", error, action);
    try {
        if (isExtensionContextValid()) {
            chrome.runtime.sendMessage({
                action: "userAction",
                data: {
                    type: "internalContentScriptError",
                    message: error.message,
                    stack: error.stack,
                    context: "sendUserActionWithCorrelation",
                    failedActionType: action ? action.type : "unknown",
                    timestamp: new Date().toISOString()
                }
            });
        }
    } catch (sendError) {
        console.error("[CPCT Content Script] Failed to send internal error report:", sendError);
    }
  }
}


function setupEventListeners() {
  console.log("[CPCT Content Script] Setting up event listeners...");

  function getSelector(element) {
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
          console.warn("[CPCT Content Script] Error generating selector:", e);
          return null;
      }
  }

  function getTargetInfo(element) {
      if (!element) return null;
      return {
          tagName: element.tagName,
          id: element.id || null,
          classes: element.classList ? Array.from(element.classList) : [],
          selector: getSelector(element),
          name: element.name || null,
          role: element.getAttribute("role") || null,
          ariaLabel: element.getAttribute("aria-label") || null,
          text: element.innerText ? element.innerText.substring(0, 100) : null
      };
  }

  document.addEventListener("click", (event) => {
    sendUserActionWithCorrelation({
      type: "click",
      target: getTargetInfo(event.target),
      timestamp: new Date().toISOString(),
      position: { x: event.clientX, y: event.clientY }
    });
  }, true);

  let keyBuffer = "";
  let keyTimer = null;
  document.addEventListener("keydown", (event) => {
    if (["Control", "Shift", "Alt", "Meta"].includes(event.key)) return;

    const targetInfo = getTargetInfo(event.target);
    let valueToLog = event.key;

    const isSensitive = event.target.type === "password" || event.target.name?.toLowerCase().includes("password");
    if (isSensitive) {
        valueToLog = "***";
    }

    clearTimeout(keyTimer);
    keyBuffer += valueToLog;
    keyTimer = setTimeout(() => {
        if (keyBuffer) {
            sendUserActionWithCorrelation({
                type: "keyInput",
                target: targetInfo,
                value: keyBuffer,
                timestamp: new Date().toISOString()
            });
            keyBuffer = "";
        }
    }, 1000);

    if (event.key === "Enter" || event.key === "Tab") {
        clearTimeout(keyTimer); 
        if (keyBuffer) {
             sendUserActionWithCorrelation({
                type: "keyInput",
                target: targetInfo,
                value: keyBuffer,
                timestamp: new Date().toISOString()
            });
            keyBuffer = "";
        }
        sendUserActionWithCorrelation({
            type: "keyDownSpecific",
            target: targetInfo,
            key: event.key,
            code: event.code,
            timestamp: new Date().toISOString()
        });
    }

  }, true);

  window.addEventListener("focus", () => {
    focusState = true;
    sendUserActionWithCorrelation({
      type: "windowFocus",
      timestamp: new Date().toISOString()
    });
  }, true);

  window.addEventListener("blur", () => {
    focusState = false;
    sendUserActionWithCorrelation({
      type: "windowBlur",
      timestamp: new Date().toISOString()
    });
  }, true);

  let scrollTimer = null;
  document.addEventListener("scroll", () => {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => {
      sendUserActionWithCorrelation({
        type: "scroll",
        scrollPosition: { x: window.scrollX, y: window.scrollY },
        timestamp: new Date().toISOString()
      });
    }, 500);
  }, true);

  document.addEventListener("change", (event) => {
    const targetInfo = getTargetInfo(event.target);
    let value = event.target.value;
    const isSensitive = event.target.type === "password" || event.target.name?.toLowerCase().includes("password");
    if (isSensitive) {
        value = "***";
    }
    sendUserActionWithCorrelation({
      type: "change",
      target: targetInfo,
      value: value,
      timestamp: new Date().toISOString()
    });
  }, true);

  window.addEventListener("error", (event) => {
      sendUserActionWithCorrelation({
          type: "pageError",
          message: event.message,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          error: event.error ? { message: event.error.message, stack: event.error.stack } : null,
          timestamp: new Date().toISOString()
      });
  });

  window.addEventListener("unhandledrejection", (event) => {
      sendUserActionWithCorrelation({
          type: "pageError", // tratar erro da página
          message: "Unhandled promise rejection",
          reason: event.reason ? String(event.reason) : null,
          timestamp: new Date().toISOString()
      });
  });

  console.log("[CPCT Content Script] Event listeners set up.");
}

function extractPageMetadata() {
  if (!isExtensionContextValid()) return;
  console.log("[CPCT Content Script] Extracting page metadata...");
  const metadata = {
    title: document.title,
    url: window.location.href,
    referrer: document.referrer,
    charset: document.characterSet,
    contentType: document.contentType,
    language: document.documentElement.lang || navigator.language,
    metaTags: Array.from(document.querySelectorAll("meta")).map(tag => ({ name: tag.name, content: tag.content })),
    linkTags: Array.from(document.querySelectorAll("link")).map(tag => ({ rel: tag.rel, href: tag.href })),
    scripts: Array.from(document.querySelectorAll("script")).map(tag => ({ src: tag.src })),
    service: identifyGoogleService(),
    view: identifyCurrentView()
  };
  sendUserActionWithCorrelation({
    type: "pageMetadata",
    data: metadata,
    timestamp: new Date().toISOString()
  });
}

let lastMousePosition = { x: 0, y: 0 };
let mouseMoved = false;
document.addEventListener("mousemove", (event) => {
    lastMousePosition = { x: event.clientX, y: event.clientY };
    mouseMoved = true;
}, { capture: true, passive: true });

function sendMouseMovementData() {
    if (mouseMoved && isExtensionContextValid()) {
        sendUserActionWithCorrelation({
            type: "mouseMovement",
            position: lastMousePosition,
            timestamp: new Date().toISOString()
        });
        mouseMoved = false; // Reseta flag
    }
}

function observeDOMChanges() {
  if (!isExtensionContextValid()) return;
  console.log("[CPCT Content Script] Setting up DOM observer...");
  const observer = new MutationObserver((mutations) => {
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: false
  });
  console.log("[CPCT Content Script] DOM observer active.");
}

function setupDocumentContentCapture() {
    if (!isExtensionContextValid()) return;
    console.log("[CPCT Content Script] Setting up document content capture...");
    const editorElement = document.querySelector("textarea.docs-texteventtarget-iframe") || document.body; // Adjust selector

    if (editorElement) {
        const debouncedSendContent = debounce(() => {
            if (documentChangeBuffer.length > 0 && isExtensionContextValid()) {
                sendUserActionWithCorrelation({
                    type: "documentContent",
                    documentId: window.location.pathname,
                    changes: documentChangeBuffer,
                    timestamp: new Date().toISOString()
                });
                documentChangeBuffer = [];
            }
        }, 5000);

        editorElement.addEventListener("input", (event) => {
            documentChangeBuffer.push({
                type: "input",
                timestamp: new Date().toISOString()
            });
            debouncedSendContent();
        });

        console.log("[CPCT Content Script] Document content capture active.");
    } else {
        console.warn("[CPCT Content Script] Editor element not found for content capture.");
    }
}

function debounce(func, wait) {
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

function checkRequestDataCollection() {
  if (!isExtensionContextValid()) return;
  if (!lastRequestTime || Date.now() - lastRequestTime > 60000) { // 60 seconds
    console.warn("[CPCT Content Script] No requests (XHR/Fetch) detected in the last minute.");

    // Try to verify background communication
    verifyBackgroundCommunication();

    // If injection failed initially, maybe retry?
    if (scriptInjectionAttempted && !scriptInjectedSuccessfully) {
        console.log("[CPCT Content Script] Retrying interceptor script injection...");
        injectInterceptorFile(); // Use the file injection method now
    }

    // Send diagnostic event
    sendUserActionWithCorrelation({
      type: "diagnosticEvent",
      event: "noRequestsDetected",
      details: `Last request time: ${lastRequestTime ? new Date(lastRequestTime).toISOString() : "Never"}`,
      timestamp: new Date().toISOString()
    });
  }
}

// --- Utility Functions ---

// Identify Google service based on URL
function identifyGoogleService() {
  const host = window.location.hostname;
  const path = window.location.pathname;

  if (host.includes("mail.google.com")) return "Gmail";
  if (host.includes("drive.google.com")) return "Google Drive";
  if (host.includes("docs.google.com")) return "Google Docs";
  if (host.includes("sheets.google.com")) return "Google Sheets";
  if (host.includes("slides.google.com")) return "Google Slides";
  if (host.includes("calendar.google.com")) return "Google Calendar";
  if (host.includes("meet.google.com")) return "Google Meet";
  if (host.includes("photos.google.com")) return "Google Photos";
  if (host.includes("contacts.google.com")) return "Google Contacts";
  if (host.includes("keep.google.com")) return "Google Keep";
  if (host.includes("youtube.com")) return "YouTube";
  if (host.includes("google.com") && path.includes("/maps")) return "Google Maps";
  if (host.includes("google.com") && (path === "/" || path.startsWith("/search") || path.startsWith("/webhp"))) return "Google Search";

  return "Other Google Service";
}

// Identify current view within a service
function identifyCurrentView() {
  const url = window.location.href;
  const path = window.location.pathname;
  const hash = window.location.hash;

  // Gmail
  if (url.includes("mail.google.com")) {
    if (hash.startsWith("#inbox")) return "Inbox";
    if (hash.startsWith("#sent")) return "Sent";
    if (hash.startsWith("#drafts")) return "Drafts";
    if (hash.match(/#label\/[^\/]+/)) return "Label View";
    if (hash.match(/#search\/.+/)) return "Search Results";
    if (hash.match(/#[^\/]+\/[^\/]+/)) return "Email Read View";
    return "Gmail - Other";
  }

  // Drive
  if (url.includes("drive.google.com")) {
    if (url.includes("/drive/my-drive")) return "My Drive";
    if (url.includes("/drive/shared-with-me")) return "Shared with me";
    if (url.includes("/drive/recent")) return "Recent";
    if (url.includes("/drive/starred")) return "Starred";
    if (url.includes("/drive/trash")) return "Trash";
    if (url.includes("/drive/folders/")) return "Folder View";
    if (url.includes("/drive/search")) return "Search Results";
    return "Drive - Other";
  }

  // Docs, Sheets, Slides
  if (url.includes("docs.google.com") || url.includes("sheets.google.com") || url.includes("slides.google.com")) {
    if (path.includes("/edit")) return "Edit Mode";
    if (path.includes("/view") || path.includes("/preview")) return "View Mode";
    if (path.includes("/copy")) return "Copy Document";
    if (path.match(/\/d\/[^\/]+\/?$/) || path.match(/\/d\/[^\/]+\/$/)) return "Edit Mode";
    return "Document/Sheet/Slide - Other";
  }

  // Calendar
  if (url.includes("calendar.google.com")) {
      if (url.includes("/day")) return "Day View";
      if (url.includes("/week")) return "Week View";
      if (url.includes("/month")) return "Month View";
      if (url.includes("/year")) return "Year View";
      if (url.includes("/agenda")) return "Agenda View";
      if (url.includes("/eventedit")) return "Event Edit";
      return "Calendar - Other";
  }

  // Google Search
  if (url.includes("google.com/search") || url.includes("google.com/webhp")) {
      const params = new URLSearchParams(window.location.search);
      if (params.get("tbm") === "isch") return "Image Search";
      if (params.get("tbm") === "vid") return "Video Search";
      if (params.get("tbm") === "nws") return "News Search";
      if (params.get("tbm") === "shop") return "Shopping Search";
      return "Web Search Results";
  }

  return "Default View";
}

// Get location info
function getLocationInfo() {
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

// --- Initialization Function ---
function initialize() {
  if (!isExtensionContextValid()) {
    console.error("[CPCT Content Script] Context invalid at initialization. Aborting.");
    return;
  }

  // Target specific domains
  if (!window.location.hostname.endsWith("google.com") && !window.location.hostname.endsWith("youtube.com")) {
    console.log("CPCT Data Safe: Not a target domain. Script inactive.");
    return;
  }

  console.log("CPCT Data Safe: Content script initializing on", window.location.hostname);

  // Initial verification of background communication
  verifyBackgroundCommunication();

  pageLoadTime = performance.now();
  focusState = document.hasFocus();

  // Send initialization event after a short delay
  setTimeout(() => {
    try {
      if (isExtensionContextValid()) {
        sendUserActionWithCorrelation({
          type: "contentScriptInitialized",
          timestamp: new Date().toISOString()
        });
      }
    } catch (e) {
      console.error("[CPCT Content Script] Error sending initialization event:", e);
    }
  }, 1000);

  // Set up core event listeners
  try {
    setupEventListeners();
  } catch (e) {
    console.error("[CPCT Content Script] Error setting up event listeners:", e);
  }

  // Extract metadata after a delay
  try {
    setTimeout(extractPageMetadata, 2000);
  } catch (e) {
    console.error("[CPCT Content Script] Error scheduling metadata extraction:", e);
  }

  // Set up periodic tasks
  const mouseMovementInterval = setInterval(() => {
    if (!isExtensionContextValid()) { clearInterval(mouseMovementInterval); return; }
    try { sendMouseMovementData(); } catch (e) { console.error("Error sending mouse movement:", e); }
  }, 5000);

  const cleanupInterval = setInterval(() => {
    if (!isExtensionContextValid()) { clearInterval(cleanupInterval); return; }
  }, 30000);

  const requestCheckInterval = setInterval(() => {
      if (!isExtensionContextValid()) { clearInterval(requestCheckInterval); return; }
      try { checkRequestDataCollection(); } catch (e) { console.error("Error checking request collection:", e); }
  }, 60000);

  // Set up features requiring specific page context
  if (window.location.hostname.includes("docs.google.com") ||
      window.location.hostname.includes("sheets.google.com") ||
      window.location.hostname.includes("slides.google.com")) {
    try {
      setTimeout(setupDocumentContentCapture, 3000);
    } catch (e) {
      console.error("Error scheduling document content capture:", e);
    }
  }

  // Monitor DOM changes
  try {
    observeDOMChanges();
  } catch (e) {
    console.error("Error setting up DOM observer:", e);
  }

  console.log("CPCT Data Safe: Content script initialization complete.");
}

