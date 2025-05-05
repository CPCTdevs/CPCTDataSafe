#!/usr/bin/env python3
from flask import Flask, request, jsonify, make_response
import os
import json
from datetime import datetime
from functools import wraps
from flask_cors import CORS
import uuid
import logging
import pandas as pd # Import pandas
from pathlib import Path # Use pathlib for path manipulation
import re
import threading # To run CSV processing in background (optional but good practice)

app = Flask(__name__)

# --- Configurações ---
# Configuração CORS aprimorada
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": ["chrome-extension://*", "http://localhost:*", "https://localhost:*"]}},
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     expose_headers=["Content-Type", "X-API-Key"])

# Configurações da aplicação
app.config.update({
    'MAX_CONTENT_LENGTH': 50 * 1024 * 1024,  # 50MB
    'DATA_FOLDER': Path('data'), # Pasta para salvar JSONs originais (opcional)
    'CSV_OUTPUT_FOLDER': Path('user_csvs'), # Pasta para salvar CSVs processados
    'API_VERSION': 'v1',
    'API_TOKENS': {
        "12345abcde": {"user": "admin", "role": "admin"},
        "abcd123": {"user": "cpct_extension", "role": "extension"},
        "40028922": {"user": "sniffer_extension", "role": "extension"}
    }
})

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Garantir pastas de dados e CSV
app.config['DATA_FOLDER'].mkdir(exist_ok=True)
app.config['CSV_OUTPUT_FOLDER'].mkdir(exist_ok=True)

# --- Funções Auxiliares para Processamento CSV ---

def sanitize_filename(name):
    """Remove caracteres inválidos para nomes de arquivo."""
    name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)
    return name

def extract_data_from_json(data, source_filename="api_request"):
    """Extrai dados do JSON recebido para formato de linha de DataFrame."""
    user_id = data.get('userId')
    username = data.get('username')
    upload_timestamp = data.get('uploadTimestamp')

    if not user_id or not username:
        logger.warning(f"userId ou username ausente nos dados recebidos. Pulando processamento CSV.")
        return [], None, None # Retorna lista vazia e None para user_id/username

    rows = []

    # Processar userActions
    for action in data.get('userActions', []):
        row = {
            'userId': user_id,
            'username': username,
            'uploadTimestamp': upload_timestamp,
            'eventType': 'userAction',
            'actionType': action.get('type'),
            'timestamp': action.get('timestamp'),
            'correlationId': action.get('correlationId'),
            'url': action.get('pageContext', {}).get('url'),
            'pageTitle': action.get('pageContext', {}).get('title'),
            'target_tagName': action.get('target', {}).get('tagName'),
            'target_selector': action.get('target', {}).get('selector'),
            'target_text': action.get('target', {}).get('text'),
            'inputValue': action.get('value'),
            'keyPressed': action.get('key'),
            'scrollX': action.get('scrollPosition', {}).get('x'),
            'scrollY': action.get('scrollPosition', {}).get('y'),
            'requestUrl': None,
            'requestMethod': None,
            'requestStatusCode': None,
            'requestId': None,
            'content': None,
            'sourceFile': source_filename
        }
        rows.append(row)

    # Processar requests
    for req in data.get('requests', []):
        row = {
            'userId': user_id,
            'username': username,
            'uploadTimestamp': upload_timestamp,
            'eventType': 'request',
            'actionType': None,
            'timestamp': req.get('timestamp'),
            'correlationId': None,
            'url': None,
            'pageTitle': None,
            'target_tagName': None,
            'target_selector': None,
            'target_text': None,
            'inputValue': None,
            'keyPressed': None,
            'scrollX': None,
            'scrollY': None,
            'requestUrl': req.get('url'),
            'requestMethod': req.get('method'),
            'requestStatusCode': req.get('statusCode'),
            'requestId': req.get('requestId'),
            'content': None,
            'sourceFile': source_filename
        }
        rows.append(row)

    # Processar documentContents
    for content_item in data.get('documentContents', []):
        row = {
            'userId': user_id,
            'username': username,
            'uploadTimestamp': upload_timestamp,
            'eventType': 'documentContent',
            'actionType': content_item.get('type'),
            'timestamp': content_item.get('timestamp'),
            'correlationId': content_item.get('correlationId'),
            'url': content_item.get('pageContext', {}).get('url'),
            'pageTitle': content_item.get('pageContext', {}).get('title'),
            'target_tagName': None,
            'target_selector': None,
            'target_text': None,
            'inputValue': None,
            'keyPressed': None,
            'scrollX': None,
            'scrollY': None,
            'requestUrl': None,
            'requestMethod': None,
            'requestStatusCode': None,
            'requestId': None,
            'content': content_item.get('content'),
            'sourceFile': source_filename
        }
        rows.append(row)

    return rows, user_id, username

def update_user_csv(user_id, username, new_data_rows):
    """Atualiza ou cria o arquivo CSV para um usuário específico."""
    if not user_id or not username or not new_data_rows:
        logger.warning("Dados insuficientes para atualizar CSV (userId, username ou dados ausentes).")
        return

    output_folder = app.config['CSV_OUTPUT_FOLDER']
    csv_filename_base = f"{username}_{user_id}"
    csv_filename = sanitize_filename(csv_filename_base) + ".csv"
    output_path = output_folder / csv_filename

    logger.info(f"Preparando para atualizar CSV para usuário '{username}' ({user_id}) em {output_path}")

    df_new = pd.DataFrame(new_data_rows)

    # Garantir colunas e ordem
    expected_cols = [
        'userId', 'username', 'uploadTimestamp', 'eventType', 'actionType',
        'timestamp', 'correlationId', 'url', 'pageTitle', 'target_tagName',
        'target_selector', 'target_text', 'inputValue', 'keyPressed',
        'scrollX', 'scrollY', 'requestUrl', 'requestMethod',
        'requestStatusCode', 'requestId', 'content', 'sourceFile'
    ]
    for col in expected_cols:
        if col not in df_new.columns:
            df_new[col] = None
    df_new = df_new[expected_cols]

    df_to_save = pd.DataFrame()

    # Lock para evitar condição de corrida se a API for muito concorrida (simplificado)
    # Uma solução mais robusta usaria bloqueio de arquivo ou um banco de dados.
    lock = threading.Lock()
    with lock:
        try:
            if output_path.exists():
                logger.debug(f"Lendo CSV existente: {output_path}")
                try:
                    df_existing = pd.read_csv(output_path)
                    df_combined = pd.concat([df_existing, df_new], ignore_index=True)
                    logger.debug(f"Combinado {len(df_existing)} registros existentes com {len(df_new)} novos.")
                    # Ordenar e remover duplicatas (opcional, mas recomendado)
                    df_to_save = df_combined.sort_values(by='timestamp').reset_index(drop=True)
                    # Exemplo de remoção de duplicatas (ajuste as colunas conforme necessário)
                    # df_to_save = df_to_save.drop_duplicates(subset=['timestamp', 'eventType', 'correlationId', 'requestId', 'actionType'], keep='last')
                except pd.errors.EmptyDataError:
                    logger.warning(f"CSV existente {output_path} está vazio. Sobrescrevendo.")
                    df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)
                except Exception as read_err:
                    logger.error(f"Erro ao ler CSV existente {output_path}: {read_err}. Tentando salvar apenas novos dados.")
                    df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)
            else:
                logger.debug(f"CSV não existente. Criando novo arquivo: {output_path}")
                df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)

            # Salvar
            if not df_to_save.empty:
                df_to_save.to_csv(output_path, index=False, encoding='utf-8')
                logger.info(f"CSV salvo com sucesso para {user_id} em {output_path}")
            else:
                logger.warning(f"Nenhum dado para salvar para o usuário {user_id} após processamento.")

        except Exception as e:
            logger.error(f"Erro GERAL ao processar/salvar CSV para {user_id} em {output_path}: {e}")

# --- Endpoints da API ---

# Health check endpoint
@app.route('/health', methods=['GET'])
@app.route('/data/health', methods=['GET'])
def health_check():
    """Endpoint para verificação de saúde da API"""
    try:
        # Verifica se as pastas necessárias existem
        data_folder_exists = app.config['DATA_FOLDER'].exists()
        csv_folder_exists = app.config['CSV_OUTPUT_FOLDER'].exists()
        
        # Tenta escrever um arquivo temporário para verificar permissões
        test_file = app.config['DATA_FOLDER'] / '.health_check'
        can_write = True
        try:
            with open(test_file, 'w') as f:
                f.write('health check')
            test_file.unlink()  # Remove o arquivo de teste
        except:
            can_write = False
        
        status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': app.config['API_VERSION'],
            'checks': {
                'data_folder_exists': data_folder_exists,
                'csv_folder_exists': csv_folder_exists,
                'can_write_files': can_write
            }
        }
        
        # Se alguma verificação falhar, retorna status degraded
        if not all(status['checks'].values()):
            status['status'] = 'degraded'
            return jsonify(status), 503
        
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Erro no health check: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/', methods=['OPTIONS'])
@app.route('/data', methods=['OPTIONS'])
@app.route('/health', methods=['OPTIONS'])
@app.route(f'/api/{app.config["API_VERSION"]}/data', methods=['OPTIONS'])
@app.route(f'/api/{app.config["API_VERSION"]}/auth', methods=['OPTIONS'])
@app.route(f'/api/{app.config["API_VERSION"]}/user', methods=['OPTIONS'])
@app.route('/api/save', methods=['OPTIONS'])
@app.route('/api/files', methods=['OPTIONS'])
@app.route('/api/status', methods=['OPTIONS'])
@app.route('/api/verify-token', methods=['OPTIONS'])
def handle_options():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            else:
                token = auth_header
        if not token and 'X-API-Key' in request.headers:
            token = request.headers['X-API-Key']
        if not token and 'authToken' in request.args:
            token = request.args.get('authToken')
        if not token and request.is_json:
            try:
                json_data = request.get_json()
                if json_data and 'apiKey' in json_data:
                    token = json_data['apiKey']
            except:
                pass

        if not token:
            logger.warning("Token de autenticação ausente na requisição")
            return jsonify({"error": "Token de autenticação ausente"}), 401

        if token not in app.config['API_TOKENS']:
            logger.warning(f"Token inválido: {token[:5]}...")
            return jsonify({"error": "Token inválido ou expirado"}), 403

        request.current_user = app.config['API_TOKENS'][token]
        return f(*args, **kwargs)
    return decorated

# --- Endpoint Modificado para Processar CSV --- 
@app.route('/data', methods=['POST'])
def simple_save_data():
    try:
        logger.info("Recebida requisição para /data")
        token = request.headers.get('X-API-Key')

        if not token:
            logger.warning("Token de API ausente na requisição para /data")
            return jsonify({"error": "Token de API ausente"}), 401

        if token not in app.config['API_TOKENS']:
            logger.warning(f"Token inválido na requisição para /data: {token[:5]}...")
            return jsonify({"error": "Token de API inválido"}), 403

        data = request.get_json()
        if not data:
            logger.warning("Dados JSON ausentes na requisição para /data")
            return jsonify({"error": "Dados JSON ausentes"}), 400

        # --- Processamento CSV Integrado --- 
        source_filename = f"api_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json" # Nome para referência
        new_data_rows, user_id, username = extract_data_from_json(data, source_filename)

        if user_id and username and new_data_rows:
            # Executar em background para não bloquear a resposta da API
            # Nota: Para produção, considere usar um sistema de filas (Celery, RQ)
            csv_thread = threading.Thread(target=update_user_csv, args=(user_id, username, new_data_rows))
            csv_thread.start()
            logger.info(f"Processamento CSV iniciado em background para usuário {user_id}")
        else:
            logger.warning("Não foi possível iniciar o processamento CSV devido a dados ausentes.")
        # --- Fim do Processamento CSV Integrado ---

        # Opcional: Salvar o JSON original também
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        user_info = app.config['API_TOKENS'][token]
        safe_user = user_info['user'].replace(" ", "_")
        filename = f"api_data_{timestamp}_{uuid.uuid4().hex[:6]}.json"
        filepath = app.config['DATA_FOLDER'] / filename
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON original salvo em {filepath}")
        except Exception as save_err:
            logger.error(f"Erro ao salvar JSON original {filepath}: {save_err}")

        # Resposta da API (mantida como antes)
        return jsonify({
            "success": True,
            "message": "Data received and processing started.", # Mensagem atualizada
            "batchId": uuid.uuid4().hex,
            "timestamp": datetime.now().isoformat(),
            "receivedItems": {
                "requests": len(data.get('requests', [])),
                "userActions": len(data.get('userActions', [])),
                "documentContents": len(data.get('documentContents', [])),
                "profiles": len(data.get('profiles', []))
            }
            # "storageStatus": { ... } # Removido ou ajustado se o JSON não for mais salvo
        }), 201 # Usar 201 Created ou 202 Accepted se o processamento for async

    except json.JSONDecodeError:
        logger.error("JSON inválido na requisição para /data")
        return jsonify({"error": "JSON inválido"}), 400
    except Exception as e:
        logger.exception(f"Erro inesperado ao processar requisição para /data") # Usar logger.exception para incluir traceback
        return jsonify({"error": "Erro interno no processamento dos dados"}), 500

# --- Outros Endpoints (Precisam ser modificados similarmente se forem usados para receber dados a processar) ---

@app.route('/api/save', methods=['POST'])
@token_required
def save_json():
    # TODO: Implementar lógica de extração e atualização de CSV aqui, similar a simple_save_data
    # ... (obter dados, chamar extract_data_from_json, chamar update_user_csv em thread)
    logger.warning("Endpoint /api/save chamado, mas processamento CSV ainda não implementado.")
    
    return jsonify({"success": True, "message": "Data received by /api/save (CSV processing TODO)"}), 201

@app.route(f'/api/{app.config["API_VERSION"]}/data', methods=['POST'])
@token_required
def save_cpct_data():
    # TODO: Implementar lógica de extração e atualização de CSV aqui, similar a simple_save_data
    # ... (obter dados, chamar extract_data_from_json, chamar update_user_csv em thread)
    logger.warning(f"Endpoint /api/{app.config['API_VERSION']}/data chamado, mas processamento CSV ainda não implementado.")
    # Salvar JSON original (se necessário)
    # ...
    return jsonify({"success": True, "message": f"Data received by /api/{app.config['API_VERSION']}/data (CSV processing TODO)"}), 201

# --- Endpoints de Autenticação e Outros (Mantidos como antes) ---

@app.route(f'/api/{app.config["API_VERSION"]}/auth', methods=['POST', 'GET'])
def cpct_auth():
    # ... (código original mantido)
    try:
        logger.info(f"Recebida requisição de autenticação: {request.method}")
        if request.method == 'POST':
            data = request.get_json()
            logger.debug(f"Dados de autenticação: {data}")
            if not data or 'authToken' not in data:
                return jsonify({"error": "Token de autenticação ausente"}), 401
            token = data['authToken']
            if token not in app.config['API_TOKENS']:
                return jsonify({"error": "Token inválido ou expirado"}), 403
            user_info = app.config['API_TOKENS'][token]
            logger.info(f"Autenticação bem-sucedida para usuário: {user_info['user']}")
            return jsonify({
                "authenticated": True,
                "user": {"id": str(uuid.uuid4()), "username": user_info['user'], "role": user_info['role']},
                "permissions": ["upload", "download"] if user_info['role'] in ['admin', 'extension'] else ["download"],
                "expiresAt": (datetime.now().timestamp() + 86400) * 1000
            })
        else: # GET
            token = request.args.get('authToken')
            logger.debug(f"Token recebido via GET: {token}")
            if not token:
                return jsonify({"error": "Token de autenticação ausente"}), 401
            if token not in app.config['API_TOKENS']:
                return jsonify({"error": "Token inválido ou expirado"}), 403
            user_info = app.config['API_TOKENS'][token]
            logger.info(f"Verificação de token bem-sucedida para usuário: {user_info['user']}")
            return jsonify({"authenticated": True, "valid": True, "user": user_info['user'], "role": user_info['role']})
    except Exception as e:
        logger.exception(f"Erro na autenticação CPCT")
        return jsonify({"error": "Erro interno na autenticação"}), 500

@app.route(f'/api/{app.config["API_VERSION"]}/user', methods=['GET'])
@token_required
def cpct_user_info():
     # ... (código original mantido)
    try:
        user_info = request.current_user
        return jsonify({
            "id": str(uuid.uuid4()),
            "username": user_info['user'],
            "role": user_info['role'],
            "permissions": ["upload", "download"] if user_info['role'] in ['admin', 'extension'] else ["download"],
            "quotaUsed": get_user_quota_used(user_info['user']),
            "quotaTotal": 1024 * 1024 * 100, # Exemplo
            "lastLogin": datetime.now().isoformat()
        })
    except Exception as e:
        logger.exception(f"Erro ao obter informações do usuário")
        return jsonify({"error": "Erro interno ao obter informações do usuário"}), 500

def get_user_quota_used(username):
    # ... (código original mantido - calcula tamanho dos JSONs, pode precisar ajustar se JSONs não forem mais salvos)
    total_size = 0
    safe_user = username.replace(" ", "_")
    data_folder_path = app.config['DATA_FOLDER']
    try:
        for filename in os.listdir(data_folder_path):
            if safe_user in filename and filename.endswith('.json'):
                filepath = data_folder_path / filename
                total_size += os.path.getsize(filepath)
        return total_size
    except Exception as e:
        logger.error(f"Erro ao calcular quota: {str(e)}")
        return 0

@app.route('/api/files', methods=['GET'])
@token_required
def list_files():
    # ... (código original mantido - lista JSONs, pode precisar ajustar)
    try:
        files = [f for f in os.listdir(app.config['DATA_FOLDER']) if f.endswith('.json')]
        # Filtragem por usuário pode ser adicionada aqui se necessário
        return jsonify({"files": files})
    except Exception as e:
        logger.exception("Erro ao listar arquivos")
        return jsonify({"error": "Erro interno ao listar arquivos"}), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    # ... (código original mantido)
    return jsonify({
        "status": "online",
        "version": app.config['API_VERSION'],
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/verify-token', methods=['POST'])
@token_required
def verify_token_endpoint():
    # ... (código original mantido)
    user_info = request.current_user
    return jsonify({
        "valid": True,
        "user": user_info['user'],
        'role': user_info['role']
    })

# --- Execução da API ---
if __name__ == '__main__':
    # Usar host='0.0.0.0' para ser acessível externamente
    # debug=True é útil para desenvolvimento, mas desative em produção
    app.run(host='0.0.0.0', port=5000, debug=False)