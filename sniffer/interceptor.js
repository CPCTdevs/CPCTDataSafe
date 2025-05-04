(() => {
  console.log("[CPCT Interceptor] !!! script interceptor.js INICIANDO !!!");
  
  if (window.__CPCT_INTERCEPTOR_INJECTED__) {
    console.log("[CPCT Interceptor] Já injetado. Pulando.");
    return;
  }
  
  window.__CPCT_INTERCEPTOR_INJECTED__ = true;
  console.log("[CPCT Interceptor] Script rodando no contexto da página.");

  function gerarIdRequisicao() {
    return "req_" + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  function isRequisicaoRelevante(url) {
    console.log(`[CPCT Interceptor] isRequisicaoRelevante verificando URL: ${url ? url.substring(0, 100) : "indefinido"}...`);
    
    if (!url) return false;
    
    try {
      const urlParseada = new URL(url);
      if (urlParseada.protocol === "chrome-extension:") {
        console.log("[CPCT Interceptor] isRequisicaoRelevante: false (chrome-extension)");
        return false;
      }
    } catch (e) {
      console.warn(`[CPCT Interceptor] isRequisicaoRelevante: Erro ao parsear URL '${url}'. Tratando como relevante.`, e);
      return true;
    }
    
    console.log("[CPCT Interceptor] isRequisicaoRelevante: true");
    return true;
  }

  // Intercepta Fetch
  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    const url = (input instanceof Request) ? input.url : String(input);
    const metodo = (init?.method || (input instanceof Request && input.method) || "GET").toUpperCase();

    console.log(`[CPCT Interceptor] Fetch interceptado: ${metodo} ${url ? url.substring(0, 100) : "indefinido"}...`);

    if (!isRequisicaoRelevante(url)) {
      console.log(`[CPCT Interceptor] Fetch ignorado (irrelevante): ${metodo} ${url ? url.substring(0, 100) : "indefinido"}...`);
      return _fetch.apply(this, arguments);
    }

    const idRequisicao = gerarIdRequisicao();
    const inicio = performance.now();

    console.log(`[CPCT Interceptor] Fetch iniciado (relevante): ${idRequisicao} ${metodo} ${url.substring(0, 100)}...`);

    return _fetch.apply(this, arguments).then(response => {
      const duracao = performance.now() - inicio;
      console.log(`[CPCT Interceptor] Fetch completado: ${idRequisicao} Status: ${response.status}`);
      
      const clone = response.clone();
      clone.text().then(body => {
        console.log(`[CPCT Interceptor] Enviando mensagem de sucesso do fetch: ${idRequisicao}`);
        window.postMessage({
          __CPCT__: true,
          type: "fetch",
          requestId: idRequisicao,
          url,
          method: metodo,
          statusCode: response.status,
          duration: duracao,
          timestamp: new Date().toISOString(),
        }, "*");
      }).catch(erro => {
        console.warn(`[CPCT Interceptor] Erro ao ler corpo da resposta do fetch para ${idRequisicao}`, erro);
        console.log(`[CPCT Interceptor] Enviando mensagem de sucesso do fetch (erro ao ler corpo): ${idRequisicao}`);
        window.postMessage({
          __CPCT__: true,
          type: "fetch",
          requestId: idRequisicao,
          url,
          method: metodo,
          statusCode: response.status,
          duration: duracao,
          timestamp: new Date().toISOString(),
          bodyReadError: erro.message
        }, "*");
      });
      
      return response;
    }).catch(erro => {
      const duracao = performance.now() - inicio;
      console.error(`[CPCT Interceptor] Erro no fetch: ${idRequisicao}`, erro);
      console.log(`[CPCT Interceptor] Enviando mensagem de erro do fetch: ${idRequisicao}`);
      
      window.postMessage({
        __CPCT__: true,
        type: "fetchError",
        requestId: idRequisicao,
        url,
        method: metodo,
        statusCode: 0,
        error: erro.message,
        duration: duracao,
        timestamp: new Date().toISOString(),
      }, "*");
      
      throw erro;
    });
  };

  // Intercepta XHR
  const _XHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new _XHR();
    const idRequisicao = gerarIdRequisicao();
    let inicio, metodo, url;

    console.log(`[CPCT Interceptor] XMLHttpRequest criado: ${idRequisicao}`);

    const openOriginal = xhr.open;
    xhr.open = function(m, u, ...args) {
      metodo = m.toUpperCase();
      url = u;
      console.log(`[CPCT Interceptor] XHR aberto: ${idRequisicao} ${metodo} ${url ? url.substring(0, 100) : "indefinido"}...`);
      inicio = performance.now();
      return openOriginal.apply(this, [m, u, ...args]);
    };

    const sendOriginal = xhr.send;
    xhr.send = function(body) {
      console.log(`[CPCT Interceptor] XHR send chamado: ${idRequisicao}`);
      return sendOriginal.apply(this, [body]);
    };

    xhr.addEventListener("loadend", () => {
      console.log(`[CPCT Interceptor] Evento loadend do XHR: ${idRequisicao} Status: ${xhr.status}`);
      
      if (!isRequisicaoRelevante(url)) {
        console.log(`[CPCT Interceptor] XHR ignorado (irrelevante): ${idRequisicao} ${metodo} ${url ? url.substring(0, 100) : "indefinido"}...`);
        return;
      }

      if (xhr.status !== 0) {
        const duracao = performance.now() - inicio;
        console.log(`[CPCT Interceptor] XHR completado: ${idRequisicao} Status: ${xhr.status}`);
        console.log(`[CPCT Interceptor] Enviando mensagem de sucesso do xhr: ${idRequisicao}`);
        
        window.postMessage({
          __CPCT__: true,
          type: "xhr",
          requestId: idRequisicao,
          url,
          method: metodo,
          statusCode: xhr.status,
          duration: duracao,
          timestamp: new Date().toISOString(),
        }, "*");
      }
    });

    xhr.addEventListener("error", () => {
      console.log(`[CPCT Interceptor] Evento de erro do XHR: ${idRequisicao}`);
      
      if (!isRequisicaoRelevante(url)) {
        console.log(`[CPCT Interceptor] Erro do XHR ignorado (irrelevante): ${idRequisicao}`);
        return;
      }
      
      const duracao = performance.now() - inicio;
      console.error(`[CPCT Interceptor] Erro no XHR: ${idRequisicao}`);
      console.log(`[CPCT Interceptor] Enviando mensagem de erro do xhr: ${idRequisicao}`);
      
      window.postMessage({
        __CPCT__: true,
        type: "xhrError",
        requestId: idRequisicao,
        url,
        method: metodo,
        statusCode: 0,
        error: "Erro de Rede ou problema de CORS",
        duration: duracao,
        timestamp: new Date().toISOString(),
      }, "*");
    });

    xhr.addEventListener("timeout", () => {
      console.log(`[CPCT Interceptor] Evento de timeout do XHR: ${idRequisicao}`);
      
      if (!isRequisicaoRelevante(url)) {
        console.log(`[CPCT Interceptor] Timeout do XHR ignorado (irrelevante): ${idRequisicao}`);
        return;
      }
      
      const duracao = performance.now() - inicio;
      console.error(`[CPCT Interceptor] Timeout no XHR: ${idRequisicao}`);
      console.log(`[CPCT Interceptor] Enviando mensagem de erro de timeout do xhr: ${idRequisicao}`);
      
      window.postMessage({
        __CPCT__: true,
        type: "xhrError",
        requestId: idRequisicao,
        url,
        method: metodo,
        statusCode: 0,
        error: "Requisição expirou (timeout)",
        duration: duracao,
        timestamp: new Date().toISOString(),
      }, "*");
    });

    return xhr;
  };

  console.log("[CPCT Interceptor] Enviando mensagem scriptInjected.");
  window.postMessage({
    __CPCT__: true,
    type: "scriptInjected",
    timestamp: new Date().toISOString()
  }, "*");
})();