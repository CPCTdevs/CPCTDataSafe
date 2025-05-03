/**
 * Exportação de dados em formato CSV
 * CPCT Data Safe
 */

;(() => {
  window.CpctDataSafeCSV = {
    /**
     * Converte array de objetos para CSV
     * @param {Array} data - Array de objetos para converter
     * @param {Array} headers - Array de cabeçalhos
     * @param {Boolean} inPortuguese - Se deve usar cabeçalhos em português
     * @returns {String} - String CSV
     */
    convertToCSV: function (data, headers, inPortuguese = true) {
      if (!data || !data.length) {
        return ""
      }

      // Criar linha de cabeçalho e adicionar label
      const headerRow = headers.map((h) => `"${h.label}"`).join(",")

      // Criar linhas de dados
      const rows = data.map((item) => {
        return headers
          .map((header) => {
            // Obter valor usando o caminho do cabeçalho
            const value = this.getNestedValue(item, header.key)

            // Formatar valor para CSV, valores vazios nas requisições ficam com null e undefined
            if (value === null || value === undefined) {
              return '""'
            } else if (typeof value === "object") {
              // Simplificar objetos para CSV
              return `"${this.simplifyObject(value)}"`
            } else {
              // Escapar aspas duplas
              return `"${String(value).replace(/"/g, '""')}"`
            }
          })
          .join(",")
      })

      // Juntar cabeçalho e linhas pulando uma linha
      return headerRow + "\n" + rows.join("\n")
    },

    /**
     * Converte para CSV de forma mais amigável ao usuário
     * @param {Array} data - Array de objetos para converter
     * @returns {String} - String CSV formatada de maneira amigável
     */
    convertToUserFriendlyCSV: function (data) {
      if (!data || !data.length) {
        return ""
      }

      // Determinar o tipo de dados para usar cabeçalhos apropriados
      let dataType = "unknown";
      
      if (data[0].requestBody || data[0].method) {
        dataType = "requests";
      } else if (data[0].type && (data[0].target || data[0].x || data[0].y)) {
        dataType = "userActions";
      } else if (data[0].fileId || data[0].fileName) {
        dataType = "metadata";
      }

      // Cabeçalhos amigáveis com base no tipo de dados
      let friendlyHeaders = [];
      
      // Cabeçalhos para requisições
      if (dataType === "requests") {
        friendlyHeaders = [
          { key: "timestamp", label: "Data e Hora" },
          { key: "associatedTab.pageContext.service", label: "Serviço Google" },
          { key: "associatedTab.title", label: "Página Atual" },
          { key: "associatedTab.pageContext.view", label: "Visualização" },
          { key: "url", label: "URL" },
          { key: "method", label: "Método" },
          { key: "type", label: "Tipo de Requisição" },
          { key: "contentType", label: "Tipo de Conteúdo" },
          { key: "statusCode", label: "Código de Status" },
          { key: "timeInfo.totalTime", label: "Tempo de Resposta (ms)" },
          { key: "associatedUserAction.type", label: "Tipo de Ação do Usuário" },
          { key: "associatedUserAction.details.element", label: "Elemento Interagido" },
          { key: "associatedUserAction.confidenceScore", label: "Confiança da Associação (%)" }
        ];
      } 
      // Cabeçalhos para ações do usuário
      else if (dataType === "userActions") {
        friendlyHeaders = [
          { key: "timestamp", label: "Data e Hora" },
          { key: "type", label: "Tipo de Ação" },
          { key: "pageContext.service", label: "Serviço Google" },
          { key: "pageContext.title", label: "Página Atual" },
          { key: "pageContext.view", label: "Visualização" },
          { key: "target.tagName", label: "Elemento" },
          { key: "target.text", label: "Texto do Elemento" },
          { key: "target.xpath", label: "XPath" },
          { key: "pageContext.url", label: "URL" },
          { key: "x", label: "Posição X" },
          { key: "y", label: "Posição Y" },
          { key: "metadata.ctrlKey", label: "Ctrl Pressionado" },
          { key: "metadata.altKey", label: "Alt Pressionado" },
          { key: "metadata.shiftKey", label: "Shift Pressionado" },
          { key: "pageContext.sessionInfo.timeOnPage", label: "Tempo na Página (ms)" }
        ];
      } 
      // Cabeçalhos para metadados
      else if (dataType === "metadata") {
        friendlyHeaders = [
          { key: "timestamp", label: "Data e Hora" },
          { key: "source", label: "Serviço Google" },
          { key: "fileType", label: "Tipo de Arquivo" },
          { key: "fileName", label: "Nome do Arquivo" },
          { key: "fileOwner", label: "Proprietário" },
          { key: "lastModified", label: "Última Modificação" },
          { key: "fileSize", label: "Tamanho" },
          { key: "shareStatus", label: "Status de Compartilhamento" },
          { key: "url", label: "URL" },
          { key: "associatedUserAction.type", label: "Ação do Usuário Associada" }
        ];
      } 
      // Cabeçalhos genéricos para qualquer tipo de dados
      else {
        friendlyHeaders = [
          { key: "id", label: "ID" },
          { key: "timestamp", label: "Data e Hora" },
          { key: "type", label: "Tipo" },
          { key: "url", label: "URL" },
          { key: "tabId", label: "ID da Aba" },
          { key: "title", label: "Título" }
        ];
      }

      // Criar linha de cabeçalho
      const headerRow = friendlyHeaders.map((h) => `"${h.label}"`).join(",")

      // Criar linhas de dados com valores mais legíveis
      const rows = data.map((item) => {
        return friendlyHeaders
          .map((header) => {
            // Obter valor usando o caminho do cabeçalho
            let value = this.getNestedValue(item, header.key)

            // Tornar valor mais legível conforme o tipo
            value = this.makeValueUserFriendly(value, header.key);

            // Formatar valor para CSV
            if (value === null || value === undefined) {
              return '"Não disponível"'
            } else if (typeof value === "object") {
              // Simplificar objetos para CSV
              return `"${this.simplifyObject(value)}"`
            } else {
              // Escapar aspas duplas
              return `"${String(value).replace(/"/g, '""')}"`
            }
          })
          .join(",")
      })

      // Juntar cabeçalho e linhas
      return headerRow + "\n" + rows.join("\n")
    },

    /**
     * Torna um valor mais legível para o usuário
     * @param {*} value - Valor original
     * @param {String} key - Chave do campo
     * @returns {*} - Valor formatado de forma amigável
     */
    makeValueUserFriendly: function(value, key) {
      // Se valor não existe, retorna indicação
      if (value === null || value === undefined) {
        return "Não disponível";
      }

      // Formatação específica por tipo de campo
      if (key === "timestamp") {
        try {
          const date = new Date(value);
          return date.toLocaleString('pt-BR', { 
            day: '2-digit', 
            month: '2-digit', 
            year: 'numeric',
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
          });
        } catch (e) {
          return value;
        }
      }

      // Formatar tipos de ação para nomes mais amigáveis
      if (key === "type" || key.endsWith(".type")) {
        const actionTypes = {
          "click": "Clique",
          "keypress": "Tecla pressionada",
          "scroll": "Rolagem",
          "mouseMovement": "Movimento do mouse",
          "formChange": "Alteração de formulário",
          "formSubmit": "Envio de formulário",
          "tabActivated": "Aba ativada",
          "pageLoaded": "Página carregada",
          "tabClosed": "Aba fechada",
          "visibilityChange": "Mudança de visibilidade",
          "driveOperation": "Operação no Drive",
          "pageUnload": "Saída da página",
          "focus": "Foco na página",
          "blur": "Perda de foco",
          "error": "Erro JavaScript",
          "fileMetadata": "Metadados de arquivo",
          "docsEdit": "Edição no Google Docs",
          "sheetsEdit": "Edição no Google Sheets",
          "slidesEdit": "Edição no Google Slides",
          "telemetry": "Telemetria",
          "headers": "Cabeçalhos HTTP",
          "peopleProfile": "Perfil de usuário",
          "driveFiles": "Arquivos do Drive"
        };
        
        return actionTypes[value] || value;
      }

      // Formatar Serviço Google de forma compreensível
      if (key.endsWith(".service") || key === "source") {
        const services = {
          "drive": "Google Drive",
          "gmail": "Gmail",
          "docs": "Google Docs",
          "sheets": "Google Sheets",
          "slides": "Google Slides",
          "calendar": "Google Agenda",
          "meet": "Google Meet",
          "photos": "Google Fotos",
          "peopleProfile": "Google Contatos",
          "telemetry": "Telemetria Google"
        };
        
        return services[value] || value;
      }

      // Formatar pontuação de confiança como porcentagem
      if (key.endsWith("confidenceScore")) {
        if (typeof value === "number") {
          return (value * 100).toFixed(0) + "%";
        }
        return value;
      }

      // Formatar booleanos como Sim/Não
      if (typeof value === "boolean") {
        return value ? "Sim" : "Não";
      }

      // Retornar o valor original para outros tipos
      return value;
    },

    /**
     * Simplifica um objeto para representação em texto
     * @param {Object} obj - Objeto para simplificar
     * @returns {String} - Representação simplificada
     */
    simplifyObject: function (obj) {
      if (!obj) return ""

      // Para arrays, juntar valores
      if (Array.isArray(obj)) {
        return obj.map((item) => (typeof item === "object" ? this.simplifyObject(item) : String(item))).join("; ")
      }

      // Para objetos, criar pares chave-valor
      try {
        // Limitar a 5 propriedades para simplificar
        const keys = Object.keys(obj).slice(0, 5)
        const pairs = keys.map((key) => {
          const value = obj[key]
          if (typeof value === "object" && value !== null) {
            return `${key}: [objeto]`
          } else {
            return `${key}: ${value}`
          }
        })

        // Adicionar indicador se houver mais propriedades
        if (Object.keys(obj).length > 5) {
          pairs.push("...")
        }

        return pairs.join(", ")
      } catch (e) {
        return "[objeto complexo]"
      }
    },

    /**
     * Obtém valor aninhado de um objeto usando caminho com pontos
     * @param {Object} obj - Objeto para extrair valor
     * @param {String} path - Caminho com pontos (ex: "user.name")
     * @returns {*} - Valor encontrado ou undefined
     */
    getNestedValue: (obj, path) => {
      if (!obj || !path) return undefined

      const keys = path.split(".")
      let value = obj

      for (const key of keys) {
        if (value === null || value === undefined) return undefined
        value = value[key]
      }

      return value
    },

    /**
     * Faz download de dados como arquivo CSV
     * @param {Array} data - Array de objetos para converter
     * @param {Array} headers - Array de cabeçalhos
     * @param {String} filename - Nome do arquivo
     * @param {Boolean} inPortuguese - Se deve usar cabeçalhos em português
     */
    downloadCSV: function (data, headers, filename, inPortuguese = false) {
      const csv = this.convertToCSV(data, headers, inPortuguese)
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
      const url = URL.createObjectURL(blob)

      const link = document.createElement("a")
      link.setAttribute("href", url)
      link.setAttribute("download", filename)
      link.style.display = "none"

      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    },

    /**
     * Faz download de dados como arquivo CSV no formato amigável
     * @param {Array} data - Array de objetos para converter
     * @param {String} filename - Nome do arquivo
     */
    downloadUserFriendlyCSV: function (data, filename) {
      const csv = this.convertToUserFriendlyCSV(data)
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
      const url = URL.createObjectURL(blob)

      const link = document.createElement("a")
      link.setAttribute("href", url)
      link.setAttribute("download", filename)
      link.style.display = "none"

      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    },

    /**
     * Exporta todos os dados como arquivo ZIP contendo múltiplos CSVs
     * @param {Object} data - Objeto com arrays de dados
     * @param {String} filename - Nome do arquivo ZIP
     * @param {Boolean} inPortuguese - Se deve usar cabeçalhos em português
     */
    exportAllDataAsZip: function (data, filename, inPortuguese = false) {
      // Implementação direta sem JSZip para evitar dependência
      try {
        // Criar um elemento para download de cada arquivo CSV individualmente
        if (data.requests && data.requests.length) {
          // Versão padrão
          const headers = this.getHeadersForDataType("requests", inPortuguese)
          this.downloadCSV(data.requests, headers, "requisicoes.csv", inPortuguese)
          
          // Versão amigável
          this.downloadUserFriendlyCSV(data.requests, "requisicoes-amigavel.csv")
        }

        if (data.userActions && data.userActions.length) {
          // Versão padrão
          const headers = this.getHeadersForDataType("userActions", inPortuguese)
          this.downloadCSV(data.userActions, headers, "acoes-usuario.csv", inPortuguese)
          
          // Versão amigável
          this.downloadUserFriendlyCSV(data.userActions, "acoes-usuario-amigavel.csv")
        }

        if (data.headers && data.headers.length) {
          // Versão padrão
          const headers = this.getHeadersForDataType("headers", inPortuguese)
          this.downloadCSV(data.headers, headers, "cabecalhos.csv", inPortuguese)
          
          // Versão amigável
          this.downloadUserFriendlyCSV(data.headers, "cabecalhos-amigavel.csv")
        }

        if (data.metadata && data.metadata.length) {
          // Versão padrão
          const headers = this.getHeadersForDataType("metadata", inPortuguese)
          this.downloadCSV(data.metadata, headers, "metadados.csv", inPortuguese)
          
          // Versão amigável
          this.downloadUserFriendlyCSV(data.metadata, "metadados-amigavel.csv")
        }

        if (data.profiles && data.profiles.length) {
          // Versão padrão
          const headers = this.getHeadersForDataType("profiles", inPortuguese)
          this.downloadCSV(data.profiles, headers, "perfis.csv", inPortuguese)
          
          // Versão amigável
          this.downloadUserFriendlyCSV(data.profiles, "perfis-amigavel.csv")
        }
        if (data.documentContents && data.documentContents.length) {
          const headers = this.getHeadersForDataType("documentContents", inPortuguese);
          this.downloadCSV(data.documentContents, headers, "conteudo-documentos.csv", inPortuguese);
          this.downloadUserFriendlyCSV(data.documentContents, "conteudo-documentos-amigavel.csv");
        }

        return true
      } catch (e) {
        console.error("Erro ao exportar dados:", e)
        throw new Error("Erro ao exportar dados: " + e.message)
      }
    },

    /**
     * Obtém cabeçalhos para um tipo específico de dados
     * @param {String} dataType - Tipo de dados
     * @param {Boolean} inPortuguese - Se deve usar cabeçalhos em português
     * @returns {Array} - Array de objetos de cabeçalho
     */
    getHeadersForDataType: (dataType, inPortuguese = false) => {
      // Cabeçalhos comuns para todos os tipos

      if (dataType === "documentContents") {
        return commonHeaders.concat(
          inPortuguese
            ? [
                { key: "source", label: "Serviço" },
                { key: "documentId", label: "ID do Documento" },
                { key: "contentLength", label: "Tamanho do Conteúdo" },
                { key: "content", label: "Conteúdo" }
              ]
            : [
                { key: "source", label: "Service" },
                { key: "documentId", label: "Document ID" },
                { key: "contentLength", label: "Content Length" },
                { key: "content", label: "Content" }
              ]
        );
      }

      const commonHeaders = inPortuguese
        ? [
            { key: "id", label: "ID" },
            { key: "timestamp", label: "Data e Hora" },
            { key: "url", label: "URL" },
            { key: "tabId", label: "ID da Aba" },
          ]
        : [
            { key: "id", label: "ID" },
            { key: "timestamp", label: "Timestamp" },
            { key: "url", label: "URL" },
            { key: "tabId", label: "Tab ID" },
          ]

      // Cabeçalhos específicos por tipo
      switch (dataType) {
        case "requests":
          return commonHeaders.concat(
            inPortuguese
              ? [
                  { key: "method", label: "Método" },
                  { key: "type", label: "Tipo" },
                  { key: "associatedTab.title", label: "Título da Aba" },
                  { key: "associatedUserAction.type", label: "Tipo de Ação do Usuário" },
                  { key: "associatedTab.pageContext.service", label: "Serviço Google" },
                  { key: "associatedTab.pageContext.view", label: "Visualização" },
                  { key: "contentType", label: "Tipo de Conteúdo" },
                  { key: "statusCode", label: "Código de Status" },
                  { key: "timeInfo.totalTime", label: "Tempo de Resposta (ms)" },
                ]
              : [
                  { key: "method", label: "Method" },
                  { key: "type", label: "Type" },
                  { key: "associatedTab.title", label: "Tab Title" },
                  { key: "associatedUserAction.type", label: "User Action Type" },
                  { key: "associatedTab.pageContext.service", label: "Google Service" },
                  { key: "associatedTab.pageContext.view", label: "View" },
                  { key: "contentType", label: "Content Type" },
                  { key: "statusCode", label: "Status Code" },
                  { key: "timeInfo.totalTime", label: "Response Time (ms)" },
                ],
          )

        case "userActions":
          return commonHeaders.concat(
            inPortuguese
              ? [
                  { key: "type", label: "Tipo de Ação" },
                  { key: "title", label: "Título" },
                  { key: "timeSpentMs", label: "Tempo Gasto (ms)" },
                  { key: "pageContext.service", label: "Serviço Google" },
                  { key: "pageContext.view", label: "Visualização" },
                  { key: "target.tagName", label: "Elemento" },
                  { key: "target.text", label: "Texto do Elemento" },
                  { key: "target.xpath", label: "XPath" },
                  { key: "x", label: "Posição X" },
                  { key: "y", label: "Posição Y" },
                ]
              : [
                  { key: "type", label: "Action Type" },
                  { key: "title", label: "Title" },
                  { key: "timeSpentMs", label: "Time Spent (ms)" },
                  { key: "pageContext.service", label: "Google Service" },
                  { key: "pageContext.view", label: "View" },
                  { key: "target.tagName", label: "Element" },
                  { key: "target.text", label: "Element Text" },
                  { key: "target.xpath", label: "XPath" },
                  { key: "x", label: "Position X" },
                  { key: "y", label: "Position Y" },
                ],
          )

        case "headers":
          return commonHeaders.concat(
            inPortuguese
              ? [
                  { key: "method", label: "Método" },
                  { key: "headers", label: "Cabeçalhos" },
                  { key: "associatedTab.pageContext.service", label: "Serviço Google" },
                  { key: "associatedTab.pageContext.view", label: "Visualização" },
                ]
              : [
                  { key: "method", label: "Method" },
                  { key: "headers", label: "Headers" },
                  { key: "associatedTab.pageContext.service", label: "Google Service" },
                  { key: "associatedTab.pageContext.view", label: "View" },
                ],
          )

        case "metadata":
          return commonHeaders.concat(
            inPortuguese
              ? [
                  { key: "source", label: "Serviço Google" },
                  { key: "fileType", label: "Tipo de Arquivo" },
                  { key: "fileName", label: "Nome do Arquivo" },
                  { key: "fileOwner", label: "Proprietário" },
                  { key: "lastModified", label: "Última Modificação" },
                  { key: "fileSize", label: "Tamanho" },
                  { key: "shareStatus", label: "Status de Compartilhamento" },
                  { key: "associatedUserAction.type", label: "Ação do Usuário Associada" },
                ]
              : [
                  { key: "source", label: "Google Service" },
                  { key: "fileType", label: "File Type" },
                  { key: "fileName", label: "File Name" },
                  { key: "fileOwner", label: "Owner" },
                  { key: "lastModified", label: "Last Modified" },
                  { key: "fileSize", label: "Size" },
                  { key: "shareStatus", label: "Share Status" },
                  { key: "associatedUserAction.type", label: "Associated User Action" },
                ],
          )

        case "profiles":
          return commonHeaders.concat(
            inPortuguese
              ? [
                  { key: "method", label: "Método" },
                  { key: "type", label: "Tipo" },
                  { key: "associatedTab.pageContext.service", label: "Serviço Google" },
                  { key: "associatedUserAction.type", label: "Ação do Usuário Associada" },
                ]
              : [
                  { key: "method", label: "Method" },
                  { key: "type", label: "Type" },
                  { key: "associatedTab.pageContext.service", label: "Google Service" },
                  { key: "associatedUserAction.type", label: "Associated User Action" },
                ],
          )

        default:
          return commonHeaders
      }
    },

    /**
     * Obtém conteúdo do README em português
     * @returns {String} - Conteúdo do README
     */
    getReadmeContentPt: () => `CPCT Data Safe - Exportação de Dados
=============================================

Este arquivo contém dados coletados pela extensão CPCT Data Safe.
Os dados estão organizados em arquivos CSV separados por categoria.

Arquivos incluídos:
------------------
- requisicoes.csv: Requisições de rede capturadas
- requisicoes-amigavel.csv: Requisições em formato mais legível
- acoes-usuario.csv: Ações do usuário registradas
- acoes-usuario-amigavel.csv: Ações do usuário em formato mais legível
- cabecalhos.csv: Cabeçalhos HTTP capturados
- cabecalhos-amigavel.csv: Cabeçalhos em formato mais legível
- metadados.csv: Metadados de arquivos
- metadados-amigavel.csv: Metadados em formato mais legível
- perfis.csv: Informações de perfil
- perfis-amigavel.csv: Informações de perfil em formato mais legível

Formato:
-------
Todos os arquivos estão no formato CSV (valores separados por vírgula).
A primeira linha contém os nomes das colunas.
Os valores estão entre aspas duplas.
Os arquivos com "-amigavel" contêm os mesmos dados em formato mais legível.

Data de exportação: ${new Date().toLocaleString("pt-BR")}
`,

    /**
     * Obtém conteúdo do README em inglês
     * @returns {String} - Conteúdo do README
     */
    getReadmeContentEn: () => `CPCT Data Safe - Data Export
============================

This file contains data collected by the CPCT Data Safe extension.
The data is organized in separate CSV files by category.

Included files:
--------------
- requests.csv: Captured network requests
- requests-readable.csv: Network requests in more readable format
- user-actions.csv: Recorded user actions
- user-actions-readable.csv: User actions in more readable format
- headers.csv: Captured HTTP headers
- headers-readable.csv: HTTP headers in more readable format
- metadata.csv: File metadata
- metadata-readable.csv: File metadata in more readable format
- profiles.csv: Profile information
- profiles-readable.csv: Profile information in more readable format

Format:
------
All files are in CSV format (comma-separated values).
The first line contains the column names.
Values are enclosed in double quotes.
Files with "-readable" contain the same data in a more human-readable format.

Export date: ${new Date().toLocaleString("en-US")}
`,
  }
})()