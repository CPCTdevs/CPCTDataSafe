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
let pingInfoElement
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
  pingInfoElement = document.getElementById("ping-info")

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

  // Adicionar botão de teste de ping
  const checkPingButton = document.getElementById("check-ping")
  if (checkPingButton) {
    checkPingButton.addEventListener("click", checkApiPing)
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

// Verificar ping da API manualmente
function checkApiPing() {
  if (typeof chrome !== "undefined" && chrome.runtime) {
    statusElement.textContent = "Verificando conexão..."
    chrome.runtime.sendMessage({ action: "checkApiConnection" }, (response) => {
      if (response && response.success) {
        setTimeout(() => {
          // Atualizar dados após um breve atraso para dar tempo do ping retornar
          loadDataStats()
          statusElement.textContent = "Verificação de conexão concluída!"
          setTimeout(() => {
            statusElement.textContent = ""
          }, 2000)
        }, 1000)
      }
    })
  }
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

      // Status da API
      if (apiStatusElement) {
        if (config && config.status) {
          // Atualizar informações de status e ping
          apiStatusElement.textContent = config.status.success ? "Conectado" : "Erro de Conexão"
          apiStatusElement.className = config.status.success ? "api-info-value success" : "api-info-value error"
          
          // Exibir informações de ping se disponíveis
          if (pingInfoElement && config.status.pingTime !== null) {
            pingInfoElement.textContent = `${config.status.pingTime}ms`;
            pingInfoElement.className = config.status.pingTime < 200 ? 
                                        "api-info-value success" : 
                                        (config.status.pingTime < 500 ? "api-info-value warning" : "api-info-value error");
          } else if (pingInfoElement) {
            pingInfoElement.textContent = "N/A";
            pingInfoElement.className = "api-info-value";
          }
        } else {
          apiStatusElement.textContent = "Desconhecido"
          apiStatusElement.className = "api-info-value"
          if (pingInfoElement) {
            pingInfoElement.textContent = "N/A";
            pingInfoElement.className = "api-info-value";
          }
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
