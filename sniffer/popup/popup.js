async function handleForceUpload() {
  try {
    const response = await chrome.runtime.sendMessage({ action: "forceUpload" });
    if (response && response.success) {
      showMessage(`Dados enviados com sucesso! ${response.itemCount} itens processados.`, "success");
    } else {
      showMessage(response?.message || "Falha no envio dos dados.", "error");
    }
  } catch (error) {
    showMessage(`Erro ao enviar dados: ${error.message || "Erro desconhecido"}`, "error");
  }
}

function showMessage(message, type = "info") {
  const messageElement = document.getElementById("message");
  if (messageElement) {
    messageElement.textContent = message;
    messageElement.className = `message ${type}`;
    messageElement.style.display = "block";
    
    // Esconder a mensagem após 5 segundos
    setTimeout(() => {
      messageElement.style.display = "none";
    }, 5000);
  }
} 