(() => {
  console.log("[CPCT Interceptor] !!! interceptor.js script STARTING !!!");
  // Check if already injected
  if (window.__CPCT_INTERCEPTOR_INJECTED__) {
    console.log("[CPCT Interceptor] Already injected. Skipping.");
    return;
  }
  window.__CPCT_INTERCEPTOR_INJECTED__ = true;

  console.log("[CPCT Interceptor] Script running in page context.");

  // Helper to generate a unique ID for requests
  function generateRequestId() {
    return "req_" + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  // Helper to check if a request URL is relevant (e.g., not extension or data endpoint)
  function isRelevantRequest(url) {
      // ADDED LOG
      console.log(`[CPCT Interceptor] isRelevantRequest checking URL: ${url ? url.substring(0,100) : "undefined"}...`);
      if (!url) return false; // Ignore undefined URLs
      try {
          const parsedUrl = new URL(url);
          // Ignore requests made by the extension itself
          if (parsedUrl.protocol === "chrome-extension:") {
              console.log("[CPCT Interceptor] isRelevantRequest: false (chrome-extension)");
              return false;
          }
          // Ignore requests to the data endpoint (if defined and matches)
          // const dataEndpointHostname = "localhost"; // Example: Define your data endpoint hostname
          // if (parsedUrl.hostname === dataEndpointHostname) {
          //     console.log("[CPCT Interceptor] isRelevantRequest: false (data endpoint)");
          //     return false;
          // }
      } catch (e) {
          console.warn(`[CPCT Interceptor] isRelevantRequest: Error parsing URL '${url}'. Treating as relevant.`, e);
          // Invalid URL? Treat as relevant for now, might need refinement
          return true;
      }
      console.log("[CPCT Interceptor] isRelevantRequest: true");
      return true;
  }

  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    const url = (input instanceof Request) ? input.url : String(input);
    const method = (init?.method || (input instanceof Request && input.method) || "GET").toUpperCase();

    // ADDED LOG
    console.log(`[CPCT Interceptor] Intercepted fetch: ${method} ${url ? url.substring(0, 100) : "undefined"}...`);

    // Ignore irrelevant requests early
    if (!isRelevantRequest(url)) {
        console.log(`[CPCT Interceptor] Fetch ignored (irrelevant): ${method} ${url ? url.substring(0, 100) : "undefined"}...`);
        return _fetch.apply(this, arguments);
    }

    const requestId = generateRequestId();
    const start = performance.now();

    console.log(`[CPCT Interceptor] Fetch started (relevant): ${requestId} ${method} ${url.substring(0, 100)}...`);

    return _fetch.apply(this, arguments).then(response => {
      const duration = performance.now() - start;
      console.log(`[CPCT Interceptor] Fetch completed: ${requestId} Status: ${response.status}`);
      // Clone the response to read body without consuming original
      const clone = response.clone();
      clone.text().then(body => {
        // ADDED LOG
        console.log(`[CPCT Interceptor] Posting fetch success message: ${requestId}`);
        window.postMessage({
          __CPCT__: true,
          type: "fetch",
          requestId, url, method,
          statusCode: response.status,
          duration,
          timestamp: new Date().toISOString(),
          // responseBody: body // Optional: Consider size implications
        }, "*");
      }).catch(err => {
         console.warn(`[CPCT Interceptor] Error reading fetch response body for ${requestId}`, err);
         // ADDED LOG
         console.log(`[CPCT Interceptor] Posting fetch success message (body read error): ${requestId}`);
         window.postMessage({
          __CPCT__: true,
          type: "fetch", // Still report as fetch, but note body error
          requestId, url, method,
          statusCode: response.status,
          duration,
          timestamp: new Date().toISOString(),
          bodyReadError: err.message
        }, "*");
      });
      return response; // Return the original response
    }).catch(error => {
      const duration = performance.now() - start;
      console.error(`[CPCT Interceptor] Fetch error: ${requestId}`, error);
      // ADDED LOG
      console.log(`[CPCT Interceptor] Posting fetch error message: ${requestId}`);
      window.postMessage({
        __CPCT__: true,
        type: "fetchError",
        requestId, url, method,
        statusCode: 0,
        error: error.message,
        duration,
        timestamp: new Date().toISOString(),
      }, "*");
      throw error; // Re-throw the error
    });
  };

  const _XHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new _XHR();
    const requestId = generateRequestId();
    let start, method, url;

    // ADDED LOG
    console.log(`[CPCT Interceptor] XMLHttpRequest created: ${requestId}`);

    const origOpen = xhr.open;
    xhr.open = function(m, u, ...args) {
      method = m.toUpperCase();
      url = u;
      // ADDED LOG
      console.log(`[CPCT Interceptor] XHR opened: ${requestId} ${method} ${url ? url.substring(0, 100) : "undefined"}...`);
      // Check relevance here? If not relevant, maybe skip adding listeners?
      // For now, check relevance before posting message.
      start = performance.now();
      return origOpen.apply(this, [m, u, ...args]);
    };

    const origSend = xhr.send;
    xhr.send = function(body) {
      // ADDED LOG
      console.log(`[CPCT Interceptor] XHR send called: ${requestId}`);
      // Can capture request body here if needed
      return origSend.apply(this, [body]);
    };

    xhr.addEventListener("loadend", () => {
      // ADDED LOG
      console.log(`[CPCT Interceptor] XHR loadend event: ${requestId} Status: ${xhr.status}`);
      // Check relevance before posting
      if (!isRelevantRequest(url)) {
          console.log(`[CPCT Interceptor] XHR ignored (irrelevant): ${requestId} ${method} ${url ? url.substring(0, 100) : "undefined"}...`);
          return;
      }

      // loadend fires for success and error (status != 0)
      if (xhr.status !== 0) { // Only report if not a network error (which fires "error")
          const duration = performance.now() - start;
          console.log(`[CPCT Interceptor] XHR completed: ${requestId} Status: ${xhr.status}`);
          // ADDED LOG
          console.log(`[CPCT Interceptor] Posting xhr success message: ${requestId}`);
          window.postMessage({
            __CPCT__: true,
            type: "xhr",
            requestId, url, method,
            statusCode: xhr.status,
            duration,
            timestamp: new Date().toISOString(),
            // responseText: xhr.responseText // Optional: Consider size
          }, "*");
      }
    });

    xhr.addEventListener("error", () => {
      // ADDED LOG
      console.log(`[CPCT Interceptor] XHR error event: ${requestId}`);
      if (!isRelevantRequest(url)) {
          console.log(`[CPCT Interceptor] XHR error ignored (irrelevant): ${requestId}`);
          return;
      }
      const duration = performance.now() - start;
      console.error(`[CPCT Interceptor] XHR error: ${requestId}`);
      // ADDED LOG
      console.log(`[CPCT Interceptor] Posting xhr error message: ${requestId}`);
      window.postMessage({
        __CPCT__: true,
        type: "xhrError",
        requestId, url, method,
        statusCode: 0, // Status 0 usually indicates network error
        error: "Network Error or CORS issue",
        duration,
        timestamp: new Date().toISOString(),
      }, "*");
    });

    xhr.addEventListener("timeout", () => {
        // ADDED LOG
        console.log(`[CPCT Interceptor] XHR timeout event: ${requestId}`);
        if (!isRelevantRequest(url)) {
            console.log(`[CPCT Interceptor] XHR timeout ignored (irrelevant): ${requestId}`);
            return;
        }
        const duration = performance.now() - start;
        console.error(`[CPCT Interceptor] XHR timeout: ${requestId}`);
        // ADDED LOG
        console.log(`[CPCT Interceptor] Posting xhr timeout error message: ${requestId}`);
        window.postMessage({
            __CPCT__: true,
            type: "xhrError",
            requestId, url, method,
            statusCode: 0, // Or a specific code for timeout?
            error: "Request timed out",
            duration,
            timestamp: new Date().toISOString(),
        }, "*");
    });

    return xhr;
  };

  // Inform the content script that the injection was successful
  // ADDED LOG
  console.log("[CPCT Interceptor] Posting scriptInjected message.");
  window.postMessage({
    __CPCT__: true,
    type: "scriptInjected",
    timestamp: new Date().toISOString()
  }, "*");
})(); // IIFE ends here

