// Script para gerenciar login e registro de usuários

// Elementos do DOM
let usernameInput;
let passwordInput;
let loginButton;
let loginStatus;
let registerToggle;
let registerForm;
let newUsernameInput;
let newPasswordInput;
let confirmPasswordInput;
let registerButton;
let cancelRegisterButton;
let registerStatus;

// Inicializar quando o documento estiver carregado
document.addEventListener("DOMContentLoaded", () => {
  // Obter elementos do DOM
  usernameInput = document.getElementById("username");
  passwordInput = document.getElementById("password");
  loginButton = document.getElementById("login-button");
  loginStatus = document.getElementById("login-status");
  
  registerToggle = document.getElementById("register-toggle");
  registerForm = document.getElementById("register-form");
  newUsernameInput = document.getElementById("new-username");
  newPasswordInput = document.getElementById("new-password");
  confirmPasswordInput = document.getElementById("confirm-password");
  registerButton = document.getElementById("register-button");
  cancelRegisterButton = document.getElementById("cancel-register");
  registerStatus = document.getElementById("register-status");
  
  // Configurar event listeners
  loginButton.addEventListener("click", handleLogin);
  registerToggle.addEventListener("click", toggleRegisterForm);
  registerButton.addEventListener("click", handleRegister);
  cancelRegisterButton.addEventListener("click", toggleRegisterForm);
  
  // Verificar se o usuário já está logado
  checkLoginStatus();
});

// Verificar se o usuário já está logado
function checkLoginStatus() {
  chrome.storage.local.get(["userLoggedIn", "userId", "username"], (result) => {
    if (result.userLoggedIn) {
      // Redirecionar para a página principal
      window.location.href = "cpctDataSafePopup.html";
    }
  });
}

// Alternar exibição do formulário de registro
function toggleRegisterForm() {
  if (registerForm.style.display === "none" || registerForm.style.display === "") {
    registerForm.style.display = "block";
    registerToggle.style.display = "none";
  } else {
    registerForm.style.display = "none";
    registerToggle.style.display = "block";
    // Limpar campos e mensagens
    newUsernameInput.value = "";
    newPasswordInput.value = "";
    confirmPasswordInput.value = "";
    registerStatus.textContent = "";
    registerStatus.className = "status-message";
  }
}

// Lidar com tentativa de login
function handleLogin() {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  
  // Validar campos
  if (!username || !password) {
    showLoginStatus("Preencha todos os campos", "error");
    return;
  }
  
  // Desabilitar botão durante o processo
  loginButton.disabled = true;
  
  // Verificar credenciais
  chrome.storage.local.get(["users"], (result) => {
    const users = result.users || {};
    
    if (users[username] && users[username].password === hashPassword(password)) {
      // Login bem-sucedido
      const userId = users[username].userId;
      
      // Armazenar informações de login
      chrome.storage.local.set({
        userLoggedIn: true,
        userId: userId,
        username: username,
        lastLogin: new Date().toISOString()
      }, () => {
        // Notificar background script sobre o login
        chrome.runtime.sendMessage({
          action: "userLoggedIn",
          userId: userId,
          username: username
        });
        
        // Redirecionar para a página principal
        showLoginStatus("Login bem-sucedido! Redirecionando...", "success");
        setTimeout(() => {
          window.location.href = "cpctDataSafePopup.html";
        }, 1000);
      });
    } else {
      // Login falhou
      showLoginStatus("Usuário ou senha incorretos", "error");
      loginButton.disabled = false;
    }
  });
}

// Lidar com registro de novo usuário
function handleRegister() {
  const newUsername = newUsernameInput.value.trim();
  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  
  // Validar campos
  if (!newUsername || !newPassword || !confirmPassword) {
    showRegisterStatus("Preencha todos os campos", "error");
    return;
  }
  
  if (newPassword !== confirmPassword) {
    showRegisterStatus("As senhas não coincidem", "error");
    return;
  }
  
  if (newPassword.length < 6) {
    showRegisterStatus("A senha deve ter pelo menos 6 caracteres", "error");
    return;
  }
  
  // Desabilitar botão durante o processo
  registerButton.disabled = true;
  
  // Verificar se o usuário já existe
  chrome.storage.local.get(["users"], (result) => {
    const users = result.users || {};
    
    if (users[newUsername]) {
      showRegisterStatus("Este nome de usuário já está em uso", "error");
      registerButton.disabled = false;
      return;
    }
    
    // Gerar ID único para o usuário
    const userId = generateUniqueId();
    
    // Adicionar novo usuário
    users[newUsername] = {
      userId: userId,
      password: hashPassword(newPassword),
      createdAt: new Date().toISOString()
    };
    
    // Salvar usuários atualizados
    chrome.storage.local.set({ users: users }, () => {
      showRegisterStatus("Registro bem-sucedido! Você pode fazer login agora.", "success");
      
      // Limpar campos
      newUsernameInput.value = "";
      newPasswordInput.value = "";
      confirmPasswordInput.value = "";
      
      // Fechar formulário de registro após um atraso
      setTimeout(() => {
        toggleRegisterForm();
        registerButton.disabled = false;
      }, 2000);
    });
  });
}

// Mostrar mensagem de status no formulário de login
function showLoginStatus(message, type) {
  loginStatus.textContent = message;
  loginStatus.className = `status-message ${type}`;
}

// Mostrar mensagem de status no formulário de registro
function showRegisterStatus(message, type) {
  registerStatus.textContent = message;
  registerStatus.className = `status-message ${type}`;
}

// Gerar ID único para usuário
function generateUniqueId() {
  // Combinar timestamp com string aleatória
  const timestamp = Date.now().toString(36);
  const randomStr = Math.random().toString(36).substring(2, 10);
  return `user_${timestamp}_${randomStr}`;
}

// Função simples de hash para senhas (em produção, use bcrypt ou similar)
function hashPassword(password) {
  // Esta é uma implementação simples para demonstração
  // Em produção, use uma biblioteca de hash segura
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Converter para inteiro de 32 bits
  }
  return hash.toString(16); // Converter para string hexadecimal
}
