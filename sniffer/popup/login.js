// Login script para CPCT Data Safe

let currentForm = 'login'; // 'login' ou 'register'

// Elementos do DOM
let loginForm, registerForm, loginButton, registerButton, registerToggle, loginToggle;
let loginStatus, registerStatus;
let apiDestination, apiStatus, statusIndicator, statusText;

// Inicializar quando o DOM carregar
document.addEventListener('DOMContentLoaded', function() {
  console.log('[Login] DOM carregado, inicializando...');
  
  // Obter elementos do DOM
  initializeElements();
  
  // Configurar event listeners
  setupEventListeners();
  
  // Verificar status da API
  checkApiStatus();
  
  // Verificar se já está logado
  checkIfAlreadyLoggedIn();
  
  console.log('[Login] Inicialização completa');
});

function initializeElements() {
  // Formulários
  loginForm = document.getElementById('login-form');
  registerForm = document.getElementById('register-form');
  
  // Botões
  loginButton = document.getElementById('login-button');
  registerButton = document.getElementById('register-button');
  registerToggle = document.getElementById('register-toggle');
  loginToggle = document.getElementById('login-toggle');
  
  // Status
  loginStatus = document.getElementById('login-status');
  registerStatus = document.getElementById('register-status');
  
  // API Status
  apiDestination = document.getElementById('api-destination');
  apiStatus = document.getElementById('api-status');
  statusIndicator = document.getElementById('status-indicator');
  statusText = document.getElementById('status-text');
  
  console.log('[Login] Elementos inicializados:', {
    loginForm: !!loginForm,
    registerForm: !!registerForm,
    apiStatus: !!apiStatus
  });
}

function setupEventListeners() {
  // Formulário de login
  const loginFormElement = document.getElementById('login-form-element');
  if (loginFormElement) {
    loginFormElement.addEventListener('submit', handleLogin);
  }
  
  // Formulário de registro
  const registerFormElement = document.getElementById('register-form-element');
  if (registerFormElement) {
    registerFormElement.addEventListener('submit', handleRegister);
  }
  
  // Alternar entre login e registro
  if (registerToggle) {
    registerToggle.addEventListener('click', () => switchForm('register'));
  }
  
  if (loginToggle) {
    loginToggle.addEventListener('click', () => switchForm('login'));
  }
  
  // Verificar status da API periodicamente
  setInterval(checkApiStatus, 30000); // A cada 30 segundos
}

function switchForm(formType) {
  currentForm = formType;
  
  if (formType === 'register') {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
  } else {
    loginForm.style.display = 'block';
    registerForm.style.display = 'none';
  }
  
  // Limpar mensagens de status
  clearStatus();
}

function handleLogin(event) {
  event.preventDefault();
  
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  
  if (!username || !password) {
    showStatus('login', 'Por favor, preencha todos os campos', 'error');
    return;
  }
  
  setLoading('login', true);
  clearStatus('login');
  
  console.log('[Login] Tentando fazer login para:', username);
  
  chrome.runtime.sendMessage({
    action: 'login',
    username: username,
    password: password
  }, (response) => {
    setLoading('login', false);
    
    if (chrome.runtime.lastError) {
      console.error('[Login] Erro de comunicação:', chrome.runtime.lastError);
      showStatus('login', 'Erro de comunicação com a extensão', 'error');
      return;
    }
    
    console.log('[Login] Resposta recebida:', response);
    
    if (response && response.success) {
      showStatus('login', 'Login realizado com sucesso! Redirecionando...', 'success');
      setTimeout(() => {
        window.location.href = 'cpctDataSafePopup.html';
      }, 1500);
    } else {
      const errorMessage = response?.message || 'Erro desconhecido no login';
      showStatus('login', errorMessage, 'error');
    }
  });
}

function handleRegister(event) {
  event.preventDefault();
  
  const username = document.getElementById('new-username').value.trim();
  const email = document.getElementById('new-email').value.trim();
  const password = document.getElementById('new-password').value;
  const confirmPassword = document.getElementById('confirm-password').value;
  
  // Validações
  if (!username || !email || !password || !confirmPassword) {
    showStatus('register', 'Por favor, preencha todos os campos', 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showStatus('register', 'As senhas não coincidem', 'error');
    return;
  }
  
  if (password.length < 6) {
    showStatus('register', 'A senha deve ter pelo menos 6 caracteres', 'error');
    return;
  }
  
  // Validação de email básica
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    showStatus('register', 'Por favor, insira um email válido', 'error');
    return;
  }
  
  setLoading('register', true);
  clearStatus('register');
  
  console.log('[Login] Tentando registrar usuário:', username);
  
  chrome.runtime.sendMessage({
    action: 'register',
    username: username,
    email: email,
    password: password
  }, (response) => {
    setLoading('register', false);
    
    if (chrome.runtime.lastError) {
      console.error('[Login] Erro de comunicação:', chrome.runtime.lastError);
      showStatus('register', 'Erro de comunicação com a extensão', 'error');
      return;
    }
    
    console.log('[Login] Resposta de registro:', response);
    
    if (response && response.success) {
      showStatus('register', 'Registro realizado com sucesso! Aguarde aprovação do administrador.', 'success');
      setTimeout(() => {
        switchForm('login');
        showStatus('login', 'Conta criada! Aguarde aprovação para fazer login.', 'info');
      }, 3000);
    } else {
      const errorMessage = response?.message || 'Erro desconhecido no registro';
      showStatus('register', errorMessage, 'error');
    }
  });
}

function setLoading(formType, isLoading) {
  const button = formType === 'login' ? loginButton : registerButton;
  const buttonText = button?.querySelector('.button-text');
  const spinner = button?.querySelector('.loading-spinner');
  
  if (button) {
    button.disabled = isLoading;
    if (buttonText) {
      buttonText.style.display = isLoading ? 'none' : 'inline';
    }
    if (spinner) {
      spinner.style.display = isLoading ? 'inline-block' : 'none';
    }
  }
}

function showStatus(formType, message, type) {
  const statusElement = formType === 'login' ? loginStatus : registerStatus;
  
  if (statusElement) {
    statusElement.textContent = message;
    statusElement.className = `status-message ${type}`;
    statusElement.style.display = 'block';
    
    // Auto-ocultar após 5 segundos se for sucesso ou info
    if (type === 'success' || type === 'info') {
      setTimeout(() => {
        clearStatus(formType);
      }, 5000);
    }
  }
  
  console.log(`[Login] Status ${formType}:`, message, type);
}

function clearStatus(formType) {
  if (formType) {
    const statusElement = formType === 'login' ? loginStatus : registerStatus;
    if (statusElement) {
      statusElement.style.display = 'none';
      statusElement.textContent = '';
    }
  } else {
    // Limpar ambos
    if (loginStatus) {
      loginStatus.style.display = 'none';
      loginStatus.textContent = '';
    }
    if (registerStatus) {
      registerStatus.style.display = 'none';
      registerStatus.textContent = '';
    }
  }
}

function checkIfAlreadyLoggedIn() {
  console.log('[Login] Verificando se já está logado...');
  
  chrome.runtime.sendMessage({ action: 'getAuthStatus' }, (response) => {
    if (chrome.runtime.lastError) {
      console.log('[Login] Erro ao verificar login:', chrome.runtime.lastError);
      return;
    }
    
    console.log('[Login] Status de auth:', response);
    
    if (response && response.isAuthenticated) {
      console.log('[Login] Usuário já está logado, redirecionando...');
      window.location.href = 'cpctDataSafePopup.html';
    }
  });
}

function checkApiStatus() {
  console.log('[Login] Verificando status da API...');
  
  // Atualizar destino da API
  chrome.runtime.sendMessage({ action: 'getApiConfig' }, (config) => {
    if (apiDestination && config?.baseUrl) {
      try {
        const url = new URL(config.baseUrl);
        apiDestination.textContent = url.hostname;
        apiDestination.title = config.baseUrl;
      } catch (e) {
        apiDestination.textContent = config.baseUrl;
      }
    }
  });
  
  // Usar a função de verificação do background script
  chrome.runtime.sendMessage({ action: 'checkApiStatus' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('[Login] Erro ao verificar status da API:', chrome.runtime.lastError);
      updateApiStatus(false, { error: 'Erro de comunicação com extensão' });
      return;
    }
    
    console.log('[Login] Resposta do status da API:', response);
    
    if (response) {
      updateApiStatus(response.isOnline, response.healthData || response);
    } else {
      updateApiStatus(false, { error: 'Resposta inválida' });
    }
  });
}

function updateApiStatus(isOnline, healthData) {
  console.log('[Login] Atualizando status da API:', isOnline, healthData);
  
  let statusMessage = "Verificando...";
  
  if (isOnline === true) {
    if (healthData?.status === 'healthy') {
      statusMessage = "Conectado";
    } else if (healthData?.status === 'server_responding') {
      statusMessage = "Servidor respondendo";
    } else {
      statusMessage = "Online";
    }
  } else if (isOnline === false) {
    if (healthData?.error) {
      if (healthData.error.includes('Failed to fetch')) {
        statusMessage = "Servidor inacessível";
      } else if (healthData.error.includes('Servidor não acessível')) {
        statusMessage = "Sem conexão";
      } else {
        statusMessage = "Erro de conexão";
      }
    } else {
      statusMessage = "Offline";
    }
  }
  
  if (statusIndicator) {
    statusIndicator.className = `status-indicator ${isOnline ? 'online' : 'offline'}`;
  }
  
  if (statusText) {
    statusText.textContent = statusMessage;
  }
  
  if (apiStatus) {
    apiStatus.className = `api-info-value ${isOnline ? 'success' : 'error'}`;
    
    // Criar tooltip detalhado
    let tooltipText = `Status: ${statusMessage}\n`;
    
    if (healthData) {
      if (healthData.status === 'healthy') {
        tooltipText += `Servidor: Saudável\n`;
      } else if (healthData.status === 'server_responding') {
        tooltipText += `Servidor: Respondendo\nNota: Health endpoint pode não estar disponível\n`;
      }
      
      if (healthData.error) {
        tooltipText += `Erro: ${healthData.error}\n`;
      }
      
      if (healthData.endpoint) {
        tooltipText += `Endpoint testado: ${healthData.endpoint}\n`;
      }
    }
    
    tooltipText += `Última verificação: ${new Date().toLocaleString('pt-BR')}`;
    apiStatus.title = tooltipText;
  }
  
  // Log adicional para debug
  console.log('[Login] Status atualizado:', {
    isOnline,
    statusMessage,
    healthData: healthData
  });
}
