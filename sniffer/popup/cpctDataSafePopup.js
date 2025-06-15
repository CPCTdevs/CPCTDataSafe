// Script do popup para a extensão CPCT Data Safe

// Função para formatar timestamp compatível com o servidor
function getCompatibleTimestamp() {
  const now = new Date();
  // Formato sem milissegundos e com +00:00 ao invés de Z
  return now.toISOString().slice(0, 19) + '+00:00';
}

// Função para gerar timestamp para nomes de arquivo (formato seguro para arquivos)
function getFileTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

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
  console.log("Verificando status de login...");
  
  chrome.runtime.sendMessage({ action: 'getAuthStatus' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Erro ao verificar status de login:', chrome.runtime.lastError);
      window.location.href = "login.html";
      return;
    }
    
    console.log("Status de autenticação:", response);
    
    if (!response.isAuthenticated) {
      console.log("Usuário não autenticado, redirecionando para login...");
      window.location.href = "login.html";
      return;
    }
    
    // Armazenar informações do usuário
    currentUser = {
      userId: response.userId,
      username: response.user?.username || "Usuário",
      lastLogin: getCompatibleTimestamp()
    };
    
    console.log("Usuário autenticado:", currentUser);
    
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
  console.log("Iniciando logout...");
  
  chrome.runtime.sendMessage({ action: 'logout' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Erro ao fazer logout:', chrome.runtime.lastError);
    } else {
      console.log("Logout realizado:", response);
    }
    
    // Sempre redirecionar para login após logout
    window.location.href = "login.html";
  });
}

// Verificar status da API
function checkApiStatus() {
  console.log("checkApiStatus: Iniciando verificação...");
  
  chrome.runtime.sendMessage({ action: "checkApiStatus" }, (response) => {
    if (chrome.runtime.lastError) {
      console.error("checkApiStatus: Erro ao verificar status da API:", chrome.runtime.lastError);
      updateApiStatusDisplay(false, null);
      return;
    }
    
    if (response) {
      console.log("checkApiStatus: Resposta recebida:", response);
      updateApiStatusDisplay(response.isOnline, response.healthData);
    } else {
      console.error("checkApiStatus: Resposta inválida do background script");
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
  
  let statusText = "Verificando...";
  let statusClass = "api-info-value";
  
  if (isHealthy === true) {
    statusText = "Conectado";
    statusClass = "api-info-value success";
  } else if (isHealthy === false) {
    if (healthData && healthData.error) {
      if (healthData.error.includes('Failed to fetch')) {
        statusText = "Servidor inacessível";
      } else if (healthData.error.includes('Servidor não acessível')) {
        statusText = "Sem conexão";
      } else {
        statusText = "Erro de conexão";
      }
    } else {
      statusText = "Desconectado";
    }
    statusClass = "api-info-value error";
  }
  
  console.log("updateApiStatusDisplay: Atualizando status da API para:", statusText);
  
  apiStatusElement.textContent = statusText;
  apiStatusElement.className = statusClass;
  
  // Criar tooltip com informações adicionais
  let tooltipText = `Status: ${statusText}\n`;
  
  if (healthData) {
    if (healthData.status === 'healthy') {
      tooltipText += `Servidor: Saudável\n`;
    } else if (healthData.status === 'server_responding') {
      tooltipText += `Servidor: Respondendo (health endpoint indisponível)\n`;
    }
    
    if (healthData.note) {
      tooltipText += `Nota: ${healthData.note}\n`;
    }
    
    if (healthData.error) {
      tooltipText += `Erro: ${healthData.error}\n`;
    }
    
    if (healthData.endpoint) {
      tooltipText += `Endpoint: ${healthData.endpoint}\n`;
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
    const timestamp = getFileTimestamp()
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
    const timestamp = getFileTimestamp()
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