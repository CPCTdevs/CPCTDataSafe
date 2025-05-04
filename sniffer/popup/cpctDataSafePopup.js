// Script do popup para a extensão CPCT Data Safe

// Elementos do DOM
let statsElement
let uploadButton
let configForm
let statusElement
let lastUploadElement
let exportAllButton
let exportRequestsButton
let exportUserActionsButton
let exportHeadersButton
let exportMetadataButton
let exportProfilesButton
let apiDestinationElement
let apiStatusElement
let apiLastUploadElement
let userInfoElement
let logoutButton

// Dados atuais
let currentData = {
  requests: [],
  userActions: [],
  headers: [],
  metadata: [],
  profiles: [],
}

// Informações do usuário
let currentUser = {
  userId: null,
  username: null,
  lastLogin: null
}

// Inicializar quando o popup carregar
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM carregado, iniciando popup...");
  
  // Verificar se o usuário está logado
  checkLoginStatus();

  // Obter elementos do DOM
  statsElement = document.getElementById("data-stats")
  uploadButton = document.getElementById("force-upload")
  configForm = document.getElementById("config-form")
  statusElement = document.getElementById("status")
  lastUploadElement = document.getElementById("last-upload")
  userInfoElement = document.getElementById("user-info")
  logoutButton = document.getElementById("logout-button")

  // Elementos de informações da API
  apiDestinationElement = document.getElementById("api-destination")
  apiStatusElement = document.getElementById("api-status")
  apiLastUploadElement = document.getElementById("api-last-upload")
  
  // Verificar se os elementos foram encontrados
  console.log("Elementos da API encontrados:", {
    destination: !!apiDestinationElement,
    status: !!apiStatusElement,
    lastUpload: !!apiLastUploadElement
  });

  // Botões de exportação
  exportAllButton = document.getElementById("export-all-csv")
  exportRequestsButton = document.getElementById("export-requests")
  exportUserActionsButton = document.getElementById("export-user-actions")
  exportHeadersButton = document.getElementById("export-headers")
  exportMetadataButton = document.getElementById("export-metadata")
  exportProfilesButton = document.getElementById("export-profiles")

  // Mostrar menu dropdown ao clicar
  const exportSpecificButton = document.getElementById("export-specific")
  const dropdownContent = document.querySelector(".export-dropdown-content")

  if (exportSpecificButton && dropdownContent) {
    exportSpecificButton.addEventListener("click", (e) => {
      e.stopPropagation()
      dropdownContent.style.display = dropdownContent.style.display === "block" ? "none" : "block"
    })

    // Fechar dropdown ao clicar fora
    document.addEventListener("click", () => {
      dropdownContent.style.display = "none"
    })
  }

  // Carregar estatísticas atuais
  loadDataStats()

  // Configurar event listeners
  if (uploadButton) {
    uploadButton.addEventListener("click", forceUpload)
  }
  
  if (configForm) {
    configForm.addEventListener("submit", saveConfiguration)
  }
  
  if (logoutButton) {
    logoutButton.addEventListener("click", handleLogout)
  }

  // Configurar listeners dos botões de exportação
  if (exportAllButton) {
    exportAllButton.addEventListener("click", exportAllData)
  }
  
  if (exportRequestsButton) {
    exportRequestsButton.addEventListener("click", () => exportSpecificData("requests", "requisições"))
  }
  
  if (exportUserActionsButton) {
    exportUserActionsButton.addEventListener("click", () => exportSpecificData("userActions", "acoes-usuario"))
  }
  
  if (exportHeadersButton) {
    exportHeadersButton.addEventListener("click", () => exportSpecificData("headers", "cabecalhos"))
  }
  
  if (exportMetadataButton) {
    exportMetadataButton.addEventListener("click", () => exportSpecificData("metadata", "metadados"))
  }
  
  if (exportProfilesButton) {
    exportProfilesButton.addEventListener("click", () => exportSpecificData("profiles", "perfis"))
  }

  // Configurar intervalo de atualização
  setInterval(loadDataStats, 5000)
  
  // Verificar status da API na inicialização
  console.log("Iniciando verificação do status da API...");
  checkApiStatus()
})

// Verificar se o usuário está logado
function checkLoginStatus() {
  chrome.storage.local.get(["userLoggedIn", "userId", "username", "lastLogin"], (result) => {
    if (!result.userLoggedIn) {
      // Redirecionar para a página de login
      window.location.href = "login.html";
      return;
    }
    
    // Armazenar informações do usuário
    currentUser = {
      userId: result.userId,
      username: result.username,
      lastLogin: result.lastLogin
    };
    
    // Atualizar informações do usuário na interface
    updateUserInfo();
  });
}

// Atualizar informações do usuário na interface
function updateUserInfo() {
  if (userInfoElement && currentUser.username) {
    userInfoElement.textContent = `Usuário: ${currentUser.username}`;
    userInfoElement.title = `ID: ${currentUser.userId}\nÚltimo login: ${new Date(currentUser.lastLogin).toLocaleString("pt-BR")}`;
  }
}

// Lidar com logout do usuário
function handleLogout() {
  chrome.storage.local.set({
    userLoggedIn: false,
    userId: null,
    username: null
  }, () => {
    // Notificar background script sobre o logout
    chrome.runtime.sendMessage({
      action: "userLoggedOut"
    });
    
    // Redirecionar para a página de login
    window.location.href = "login.html";
  });
}

// Verificar status da API
function checkApiStatus() {
  console.log("checkApiStatus: Iniciando verificação...");
  
  chrome.runtime.sendMessage({ action: "getApiConfig" }, (config) => {
    console.log("checkApiStatus: Resposta do getApiConfig:", config);
    
    if (chrome.runtime.lastError) {
      console.error("checkApiStatus: Erro ao obter configuração da API:", chrome.runtime.lastError);
      updateApiStatusDisplay(false, null);
      return;
    }
    
    if (config && config.baseUrl) {
      console.log(`checkApiStatus: Fazendo requisição para ${config.baseUrl}/health`);
      
      fetch(`${config.baseUrl}/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      .then(response => {
        console.log("checkApiStatus: Status da resposta:", response.status, response.ok);
        console.log("checkApiStatus: Headers da resposta:", [...response.headers]);
        
        if (response.ok) {
          // Tenta fazer parse do JSON, mas se falhar ainda considera conectado
          response.json()
            .then(data => {
              console.log("checkApiStatus: Dados recebidos:", data);
              updateApiStatusDisplay(true, data);
            })
            .catch(jsonError => {
              console.log("checkApiStatus: Erro ao fazer parse do JSON, mas API está respondendo:", jsonError);
              updateApiStatusDisplay(true, { message: "API respondendo, mas resposta não é JSON válido" });
            });
        } else {
          console.error("checkApiStatus: API retornou status não-OK:", response.status);
          response.text().then(text => {
            console.error("checkApiStatus: Resposta da API:", text);
          });
          updateApiStatusDisplay(false, null);
        }
      })
      .catch(error => {
        console.error("checkApiStatus: Erro ao verificar status da API:", error);
        updateApiStatusDisplay(false, null);
      });
    } else {
      console.error("checkApiStatus: Configuração da API não encontrada ou inválida:", config);
      updateApiStatusDisplay(false, null);
    }
  });
}

// Atualizar exibição do status da API
function updateApiStatusDisplay(isHealthy, healthData = null) {
  console.log("updateApiStatusDisplay: Chamada com isHealthy =", isHealthy, "e healthData =", healthData);
  console.log("updateApiStatusDisplay: apiStatusElement existe?", !!apiStatusElement);
  
  if (!apiStatusElement) {
    console.error("updateApiStatusDisplay: Elemento apiStatus não encontrado!");
    console.log("updateApiStatusDisplay: Tentando encontrar elemento novamente...");
    apiStatusElement = document.getElementById("api-status");
    console.log("updateApiStatusDisplay: Elemento encontrado agora?", !!apiStatusElement);
    
    if (!apiStatusElement) {
      return;
    }
  }
  
  console.log("updateApiStatusDisplay: Atualizando status da API para:", isHealthy ? "Conectado" : "Erro de Conexão");
  
  apiStatusElement.textContent = isHealthy ? "Conectado" : "Erro de Conexão";
  apiStatusElement.className = isHealthy ? "api-info-value success" : "api-info-value error";
  
  // Criar tooltip com informações adicionais
  let tooltipText = `Status: ${isHealthy ? 'Conectado' : 'Erro de Conexão'}\n`;
  
  if (healthData) {
    tooltipText += `Versão: ${healthData.version || 'N/A'}\n`;
    if (healthData.message) {
      tooltipText += `Mensagem: ${healthData.message}\n`;
    }
    if (healthData.timestamp) {
      tooltipText += `Última atualização: ${new Date(healthData.timestamp).toLocaleString("pt-BR")}`;
    }
  }
  
  tooltipText += `\nÚltima verificação: ${new Date().toLocaleString("pt-BR")}`;
  
  apiStatusElement.title = tooltipText;
  
  console.log("updateApiStatusDisplay: Status atualizado com sucesso");
}

// Carregar estatísticas de dados do script de background
function loadDataStats() {
  if (typeof chrome !== "undefined" && chrome.runtime) {
    chrome.runtime.sendMessage({ action: "getDataStats" }, (response) => {
      if (response) {
        updateStatsDisplay(response)
        updateApiInfoDisplay(response)

        // Armazenar dados atuais para exportação
        chrome.runtime.sendMessage({ action: "getCurrentData" }, (data) => {
          if (data) {
            currentData = data
          }
        })
      }
    })
  } else {
    console.warn("Chrome runtime is not available.")
  }
}

// Atualizar a exibição de estatísticas com dados atuais
function updateStatsDisplay(stats) {
  if (!statsElement) return;
  
  statsElement.innerHTML = `
    <div class="stat-item">
      <span class="stat-label">Requisições:</span>
      <span class="stat-value">${stats.requestCount}</span>
    </div>
    <div class="stat-item">
      <span class="stat-label">Ações do Usuário:</span>
      <span class="stat-value">${stats.userActionCount}</span>
    </div>
    <div class="stat-item">
      <span class="stat-label">Cabeçalhos:</span>
      <span class="stat-value">${stats.headerCount}</span>
    </div>
    <div class="stat-item">
      <span class="stat-label">Metadados:</span>
      <span class="stat-value">${stats.metadataCount}</span>
    </div>
    <div class="stat-item">
      <span class="stat-label">Perfis:</span>
      <span class="stat-value">${stats.profileCount}</span>
    </div>
    <div class="stat-item">
      <span class="stat-label">Conteúdo de Documentos:</span>
      <span class="stat-value">${stats.documentContentCount || 0}</span>
    </div>
  `

  if (lastUploadElement) {
    if (stats.lastUploadAttempt) {
      lastUploadElement.textContent = new Date(stats.lastUploadAttempt).toLocaleString("pt-BR")
    } else {
      lastUploadElement.textContent = "Nunca"
    }
  }
}

// Atualizar informações da API
function updateApiInfoDisplay(stats) {
  if (typeof chrome !== "undefined" && chrome.runtime) {
    // Obter configuração atual da API diretamente do background
    chrome.runtime.sendMessage({ action: "getApiConfig" }, (config) => {
      if (apiDestinationElement) {
        if (config && config.baseUrl) {
          try {
            const url = new URL(config.baseUrl)
            apiDestinationElement.textContent = url.hostname
            apiDestinationElement.title = config.baseUrl
          } catch (e) {
            apiDestinationElement.textContent = config.baseUrl
          }
        } else {
          apiDestinationElement.textContent = "Configurado internamente"
        }
      }

      // Último envio
      if (apiLastUploadElement) {
        if (stats.lastUploadAttempt) {
          apiLastUploadElement.textContent = new Date(stats.lastUploadAttempt).toLocaleString("pt-BR")
        } else {
          apiLastUploadElement.textContent = "Nunca"
        }
      }
    })
  } else {
    console.warn("Chrome runtime is not available.")
  }
}

// Forçar um envio imediato dos dados coletados
function forceUpload() {
  if (!uploadButton || !statusElement) return;
  
  uploadButton.disabled = true
  statusElement.textContent = "Enviando..."

  if (typeof chrome !== "undefined" && chrome.runtime) {
    chrome.runtime.sendMessage({ 
      action: "forceUpload",
      userId: currentUser.userId
    }, (response) => {
      if (response && response.success) {
        statusElement.textContent = "Envio bem-sucedido!"
      } else {
        statusElement.textContent = `Falha no envio: ${response ? response.message : "Erro desconhecido"}`
      }

      uploadButton.disabled = false

      // Limpar status após um atraso
      setTimeout(() => {
        statusElement.textContent = ""
      }, 3000)

      // Atualizar estatísticas
      loadDataStats()
    })
  } else {
    console.warn("Chrome runtime is not available.")
  }
}

// Salvar configuração (mantido para compatibilidade, mas não usado)
function saveConfiguration(event) {
  event.preventDefault()
  showStatus("Configuração da API é definida internamente", "info")
}

// Exportar todos os dados como CSV
function exportAllData() {
  if (isDataEmpty()) {
    showStatus("Não há dados para exportar", "error")
    return
  }

  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const result = window.CpctDataSafeCSV.exportAllDataAsZip(
      currentData,
      `cpct-data-safe-exportacao-${timestamp}.zip`,
      true,
    )
    if (result) {
      showStatus("Exportação bem-sucedida!", "success")
    }
  } catch (error) {
    console.error("Falha na exportação:", error)
    showStatus("Falha na exportação: " + error.message, "error")
  }
}

// Exportar tipo específico de dados como CSV
function exportSpecificData(dataType, fileNamePart) {
  if (!currentData[dataType] || currentData[dataType].length === 0) {
    showStatus(`Não há dados de ${getDataTypeName(dataType)} para exportar`, "error")
    return
  }

  try {
    const headers = window.CpctDataSafeCSV.getHeadersForDataType(dataType, true)
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    window.CpctDataSafeCSV.downloadCSV(
      currentData[dataType],
      headers,
      `cpct-data-safe-${fileNamePart}-${timestamp}.csv`,
      true,
    )
    showStatus("Exportação bem-sucedida!", "success")
  } catch (error) {
    console.error("Falha na exportação:", error)
    showStatus("Falha na exportação: " + error.message, "error")
  }
}

// Obter nome amigável para tipo de dados
function getDataTypeName(dataType) {
  const names = {
    requests: "requisições",
    userActions: "ações do usuário",
    headers: "cabeçalhos",
    metadata: "metadados",
    profiles: "perfis",
    documentContents: "conteúdo de documentos"
  }
  return names[dataType] || dataType
}

// Verificar se todos os dados estão vazios
function isDataEmpty() {
  return Object.values(currentData).every((arr) => !arr || arr.length === 0)
}

// Mostrar mensagem de status
function showStatus(message, type) {
  if (!statusElement) return;
  
  statusElement.textContent = message
  statusElement.className = `status-message ${type}`

  // Limpar status após um atraso
  setTimeout(() => {
    statusElement.textContent = ""
    statusElement.className = "status-message"
  }, 3000)
}

// Ouvir mensagens do script de background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "uploadComplete") {
    // Atualizar hora do último envio
    if (lastUploadElement) {
      lastUploadElement.textContent = new Date(message.timestamp).toLocaleString("pt-BR")
      lastUploadElement.className = message.success ? "success" : "error"
    }

    // Mostrar mensagem de status
    if (statusElement) {
      if (message.success) {
        statusElement.textContent = `Envio bem-sucedido! ${message.itemCount} itens enviados.`
        statusElement.className = "status-message success"
      } else {
        statusElement.textContent = `Falha no envio: ${message.error}`
        statusElement.className = "status-message error"
      }

      // Limpar status após um atraso
      setTimeout(() => {
        statusElement.textContent = ""
        statusElement.className = "status-message"
      }, 3000)
    }

    // Atualizar estatísticas
    loadDataStats()
  }
})

// Verificar periodicamente o status da API
setInterval(checkApiStatus, 30000)