# CPCTDataSafe

Fork do projeto da IBM [user-test-logger](https://github.com/IBM/user-test-logger).

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura do Sistema](#arquitetura-do-sistema)
3. [Fluxo de Dados](#fluxo-de-dados)
4. [Componentes Principais](#componentes-principais)

   * [API](#api)
   * [Sniffer (Extensão Chrome)](#sniffer-extensão-chrome)
5. [Interceptor.js em Detalhes](#interceptorjs-em-detalhes)

   * [Processo de Injeção](#processo-de-injeção)
   * [Comunicação com Outras Partes](#comunicação-com-outras-partes)
6. [Guia de Instalação e Uso](#guia-de-instalação-e-uso)
7. [Arquitetura Detalhada e Segurança](#arquitetura-detalhada-e-segurança)


---

## Visão Geral

O **CPCTDataSafe** é uma ferramenta de captura que intercepta em tempo real a coleta de dados pessoais de telemetria e comportamento pelas Big Tech's: 

* Captura de eventos de usuário (cliques, rolagens, foco, etc.)
* Interceptação de requisições de rede (fetch e XHR)
* Geração de arquivos JSON brutos e relatórios consolidados em CSV

O componente central de interceptação é o **`interceptor.js`**, responsável por "injetar" código diretamente no contexto da página para monitorar todas as chamadas de rede.

---

## Arquitetura do Sistema

1. **Extensão Chrome (Sniffer)**

   * **Background Script**: gerencia a autenticação e comunicação com a API.
   * **Content Script**: injeta o `interceptor.js`.
   * **Interceptor Script**: roda diretamente na página.
   * **Popup/UI**: interface para login, estatísticas e exportação de dados.

2. **Servidor API**

   * **Endpoints REST**: recebem e autenticam pacotes de dados.
   * **Processamento de Payload**: valida, enriquece e formata dados.
   * **Armazenamento**: persiste JSON brutos e gera CSV consolidados.

Visualização simplificada:

<img src="Static/Diagrama.png">

## Fluxo de Dados

1. **Captura de Evento**: o usuário interage com a página (clique, rolagem, foco).
2. **Content Script**: registra eventos e injeta o `interceptor.js`.
3. **Interceptor.js**: coleta dados de rede.
4. **background.js**: recebe informações, CRIPTOGRAFA e armazena temporariamente (Cache)
5. **Comunicação Interna**: `interceptor.js` envia mensagens para o Content Script; em seguida, o Background Script dispara chamadas para a API (dados já criptografados).
6. **API**: recebe dados criptografados, DESCRIPTOGRAFA, gera logs JSON e atualiza CSV.

---

## Eventos Capturados pelo CPCTDataSafe

O **CPCTDataSafe** captura aproximadamente **20 tipos diferentes de eventos**, agrupados em quatro categorias principais:

### 1. Eventos de Interação do Usuário

* **click**: Cliques do mouse em elementos da página
* **keyInput**: Entrada de texto em campos (agrupada para eficiência)
* **keyDownSpecific**: Teclas específicas como Enter e Tab
* **scroll**: Rolagem da página
* **mouseMovement**: Movimento do cursor do mouse
* **change**: Alterações em campos de formulário
* **windowFocus**: Quando a janela/aba ganha foco
* **windowBlur**: Quando a janela/aba perde foco

### 2. Eventos de Rede

* **fetch**: Requisições usando a API Fetch
* **fetchError**: Erros em requisições Fetch
* **xhr**: Requisições usando XMLHttpRequest
* **xhrError**: Erros em requisições XHR
* **timeout**: Timeouts em requisições XHR

### 3. Eventos de Sistema e Diagnóstico

* **contentScriptInitialized**: Inicialização do content script
* **scriptInjected**: Confirmação de injeção bem-sucedida do interceptor
* **diagnosticEvent**: Eventos de diagnóstico do sistema
* **internalContentScriptError**: Erros internos do content script
* **pageError**: Erros JavaScript na página, incluindo rejeições de promises não tratadas

### 4. Eventos de Metadados e Conteúdo

* **pageMetadata**: Metadados da página (título, URL, referenciador, metatags, etc.)
* **documentContent**: Conteúdo de documentos (especialmente em aplicativos Google como Docs, Sheets)

Cada evento capturado inclui essas informações:

* Timestamp preciso
* ID de correlação para relacionar eventos
* Contexto da página (URL, título, serviço identificado)
* Informações do alvo da interação (para eventos de usuário)
* Dados de performance do navegador

---

## Componentes Principais

### API

* **Linguagem/Framework**: Python (Flask).
* **Endpoint Principal**: `/data` (POST).
* **Fluxo Interno**:

  1. Autenticação via Bearer token.
  2. Persistência:

     * JSON brutos no diretório data.
     * Consolidação e simplificação dos json's por usuário no diretório `user_csvs` com apontamento para os arquivos originais.

### Sniffer (Extensão Chrome)

#### Content Script (`content-script.js`)

* Carregado conforme `matches` no `manifest.json`.

* Injeta dinamicamente o `interceptor.js` no DOM.

* Monitora `window.postMessage` para capturar dados enviados pelo `interceptor.js`.

#### Background Script (`background.js`)

* Recebe mensagens do Content Script.
* Acumula e envia lotes de dados (ou individualmente) para a API.

#### Configuração (`manifest.json`)

```json
{
  "manifest_version": 3,
  "name": "CPCTDataSafe Sniffer",
  "permissions": ["webRequest","tabs","scripting","storage","activeTab"],
  "host_permissions": ["<all_urls>"],
  "background": {"service_worker": "background.js"},
  "content_scripts": [{"matches":["<all_urls>"],"js":["content-script.js"]}]
}
```

---

## Interceptor.js em Detalhes

O **`interceptor.js`** é injetado no contexto da página para monitorar chamadas de rede que não são possíveis capturar com content-script.

### Processo de Injeção

1. Content Script cria `<script>` apontando para `interceptor.js`.
2. Navegador carrega e executa o arquivo no contexto da página.
3. Elemento `<script>` é removido após o `onload` — o código permanece em execução.

### Comunicação com Outras Partes

| Origem            | Destino           | Mecanismo                    |
| ----------------- | ----------------- | ---------------------------- |
| interceptor.js    | Content Script    | `window.postMessage`         |
| Content Script    | Background Script | `chrome.runtime.sendMessage` |
| Background Script | API Server        | `fetch()` POST `/logs`       |

---

## Guia de Instalação e Uso

1. **Clonar repositório**:

   ```bash
   git clone https://github.com/CPCTdevs/CPCTDataSafe.git
   ```

2. **API**:

   ```bash
   cd CPCTDataSafe/api
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   deactivate
   sudo venv/bin/python server.py
   ```

3. **Extensão Chrome**:

   * Acesse `chrome://extensions`, ative modo desenvolvedor.
   * Clique em "Carregar sem compactação" e selecione `CPCTDataSafe/sniffer/`.
   * No `sniffer/config.js`, defina `API_ENDPOINT` e `API_KEY`.

4. **Uso**:

   * Abra qualquer página web de host Google e capture tráfego e ações de usuário na UI.
   * Utilize o popup para visualizar estatísticas e exportar relatórios.

---

## Estrutura de Arquivos

```
CPCTDataSafe/
├─ api/
│  ├─ api.py           # Servidor API e lógica principal
│  ├─ requirements.txt # Dependências Python
│  ├─ api_server.log   # Logs do servidor
│  ├─ keys/           # Diretório com chave RSA privada
│  └─ utils/          # Utilitários e funções auxiliares
├─ sniffer/
│  ├─ manifest.json    # Definições da extensão Chrome
│  ├─ config.js        # Configurações (endpoint e chaves)
│  ├─ content-script.js # Injeção de interceptor e listener
│  ├─ interceptor.js   # Monkey-patch de fetch/XHR
│  ├─ background.js    # Agregação e envio de dados
│  ├─ package.json     # Dependências e scripts npm
│  ├─ keys/           # Diretório com chave RSA publica
│  ├─ utils/          # Utilitários e funções auxiliares
│  ├─ images/         # Recursos visuais
│  └─ popup/          # Interface do usuário (HTML, CSS, JS)
|─ Static/            # Recursos estáticos (imagens, diagramas)
```

**Tipos de Dados**

* **Eventos de Usuário**: click, scroll, mouseMovement, focus/blur etc.
* **Requisições de Rede**: fetch, XHR, status, duração, método.
* **Metadados**: pageContext (URL, título, viewport), performanceData, userId/tabId.

**Formato do Payload**

```json
{
  "userId": "user_12345",
  "uploadTimestamp": "2025-05-05T10:00:00.000Z",
  "userActions": [ /* array de eventos */ ],
  "requests": [ /* array de requisições */ ]
}
```

---

## Arquitetura Detalhada e Segurança

```
[PÁGINA GOOGLE]
      │
      ▼
[interceptor.js]
      │  (Intercepta XHR/Fetch, coleta info de rede)
      └──(NÃO criptografado)──►
                │
                ▼
[content-script.js]
      │  (Coleta ações do usuário, DOM, e recebe do interceptor)
      └──(NÃO criptografado)──►
                │
                ▼
[background.js]
      │  (Recebe dados crus)
      └──(CRIPTOGRAFA)──►
                │
                ▼
      (dados agora criptografados)
                │
                ▼
[API (api.py)]
      │  (Recebe lote de dados criptografados)
      └──(DESCRIPTOGRAFA)──►
                │
                ▼
      (dados agora em texto claro)
                │
                ▼
[ARMAZENAMENTO FINAL]
      │  (JSON descriptografado e CSV em texto claro, sem coluna 'content')
```

> **Segurança e Privacidade**
>
> - **Criptografia ponta-a-ponta:** Os dados são criptografados localmente antes de qualquer armazenamento ou envio, e só são descriptografados no servidor.
> - **Redução da superfície de ataque:** Dados sensíveis nunca ficam expostos em texto claro no armazenamento local da extensão.
> - **Proteção contra extensões maliciosas:** Outras extensões ou scripts não conseguem acessar os dados coletados, mesmo que tenham acesso ao armazenamento do navegador.
> - **Resistência a ataques de dump de disco:** Mesmo que o disco do usuário seja copiado, os dados permanecem protegidos por criptografia.
> - **Autenticação de API:** O envio de dados para a API exige chave de autenticação.
> - **Sem persistência de chaves no cliente:** As chaves de descriptografia não ficam armazenadas no lado do usuário.
> - **Filtro de dados pessoais:** Antes de qualquer dado ser enviado ou armazenado, a aplicação utiliza expressões regulares para filtrar e evitar a coleta de informações pessoais sensíveis (como CPF, CNPJ, e-mail, telefone, etc).

A criptografia já no armazenamento **reduz drasticamente a superfície de ataque**, protegendo os dados mesmo que o ambiente do navegador seja comprometido.  
_Isso impede que outras extensões maliciosas ou softwares de terceiros acessem informações sensíveis armazenadas localmente e também dificulta a extração de dados em ataques de "dump" de disco._  
  
Dessa forma, a privacidade do usuário é garantida por meio de **criptografia ponta-a-ponta**, desde a coleta até o processamento final no servidor.
