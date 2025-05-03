# CPCTDataSafe

Fork adaptado das técnicas da IBM (https://github.com/IBM/user-test-logger) para auditoria de estratégias de coleta e monetização de dados de atividade online na plataformização.

## Estrutura do Repositório

```bash
CPCTDataSafe/
├─ api/
├─ sniffer/
└─ README.md
````

## API

Contém o código que expõe um endpoint HTTP para recebimento de pacotes de dados do Sniffer.

* **Fluxo**: recebe payload → faz processamento básico → grava:

  * **JSON completo** da requisição
  * **CSV** consolidado (vários JSONs de um mesmo usuário)

## Sniffer

Extensão Chrome responsável por capturar interações e solicitações de rede, enviando-as para a API.

### Dados coletados pelo Sniffer

1. **Eventos de usuário**

   * `type`: tipo de ação (`contentScriptInitialized`, `scroll`, `click`, `mouseMovement`, `windowFocus` / `windowBlur`)
   * `timestamp`: data/hora em ISO 8601
   * `correlationId`: identificador de correlação entre eventos
   * `preciseTimestamp`: milissegundos desde o carregamento da página
   * `timeFromPageLoad`: milissegundos desde o carregamento da página
   * **`pageContext`**

     * `title`, `url`, `referrer`
     * `viewport`: `{ width, height }`
     * `userAgent`, `devicePixelRatio`, `language`, `hasFocus`
     * `locationInfo`: `{ protocol, hostname, pathname, search, hash }`
     * `service`, `view`
   * **`performanceData`**

     * `memory.usedJSHeapSize`
     * `memory.totalJSHeapSize`
   * `userId`, `tabId`&#x20;

2. **Solicitações de rede**

   * `type`: `xhr` ou `fetch`
   * `requestId`: identificador único
   * `url` da requisição
   * `method`: `GET` / `POST`
   * `statusCode` HTTP
   * `duration` em milissegundos
   * `timestamp` em ISO 8601
   * `associatedUserAction` (quando aplicável)
   * `userId`, `tabId`&#x20;

---

## Como usar

1. **API**

   ```bash
   cd CPCTDataSafe/api
   pip install -r requirements.txt
   python server.py
   ```
2. **Sniffer**

   * Instale a extensão no Chrome via `chrome://extensions` (modo desenvolvedor).
   * Configure o endpoint da API em `sniffer/config.js`.
   * Navegue normalmente e observe os logs sendo enviados em tempo real.
