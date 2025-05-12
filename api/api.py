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
from concurrent.futures import ThreadPoolExecutor
from utils.decryption import Decryption
from queue import Queue, Empty
from collections import defaultdict
import time

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
    'DATA_FOLDER': Path('data'),
    'CSV_OUTPUT_FOLDER': Path('user_csvs'),
    'API_VERSION': 'v1',
    'API_TOKENS': {
        "12345abcde": {"user": "admin", "role": "admin"},
        "abcd123": {"user": "cpct_extension", "role": "extension"},
        "40028922": {"user": "sniffer_extension", "role": "extension"}
    },
    'MIN_WORKERS': 4,  # Mínimo de threads para garantir paralelismo
    'MAX_WORKERS': 8,  # Máximo de threads para processamento
    'USERS_PER_THREAD': 30,  # Número de usuários processados por thread
    'BATCH_SIZE': 20,  # Tamanho do lote por usuário
    'PROCESSING_TIMEOUT': 600,  # Timeout de 10 minutos para processamento
    'CLEANUP_INTERVAL': 3600,  # Limpeza a cada 1 hora
    'MAX_RETRIES': 3,  # Número máximo de tentativas para processar um arquivo
    'RETRY_DELAY': 5  # Tempo de espera entre tentativas (segundos)
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

# Initialize decryption utility
decryption = Decryption()

# Sistema de fila e processamento
file_queue = Queue()  # Removido limite máximo
user_file_mapping = defaultdict(list)
file_processing_lock = threading.Lock()
user_locks = defaultdict(threading.Lock)
thread_pool = ThreadPoolExecutor(max_workers=app.config['MAX_WORKERS'])
last_cleanup = datetime.now()
failed_files = defaultdict(list)  # Armazena arquivos que falharam para retry

def retry_failed_files():
    """Tenta processar novamente arquivos que falharam anteriormente."""
    global failed_files
    if not failed_files:
        return

    logger.info(f"Tentando processar {sum(len(files) for files in failed_files.values())} arquivos que falharam anteriormente")
    
    for user_id, files in list(failed_files.items()):
        for file_info in files[:]:  # Copia da lista para permitir remoção durante iteração
            try:
                # Adicionar à fila principal novamente
                file_queue.put(file_info)
                files.remove(file_info)
                logger.info(f"Arquivo {file_info.get('json_filename', 'unknown')} readicionado à fila")
            except Exception as e:
                logger.error(f"Erro ao readicionar arquivo à fila: {e}")
    
    # Limpar usuários sem arquivos pendentes
    failed_files = {k: v for k, v in failed_files.items() if v}

def process_user_batch(users_batch):
    """Processa um lote de usuários em uma thread."""
    start_time = datetime.now()
    logger.info(f"Iniciando processamento de lote com {len(users_batch)} usuários")
    
    try:
        for user_id, user_data in users_batch.items():
            username = user_data['username']
            files = user_data['files']
            
            try:
                # Usar lock específico do usuário com timeout
                if user_locks[user_id].acquire(timeout=5):
                    try:
                        logger.info(f"Processando {len(files)} arquivos para usuário {username}")
                        
                        for file_info in files:
                            retry_count = 0
                            success = False
                            
                            while not success and retry_count < app.config['MAX_RETRIES']:
                                try:
                                    json_filename = file_info['json_filename']
                                    data_rows = file_info['data_rows']
                                    
                                    # Atualizar CSV do usuário
                                    update_user_csv(user_id, username, data_rows, json_filename)
                                    
                                    # Registrar arquivo no mapeamento do usuário
                                    user_file_mapping[user_id].append(json_filename)
                                    
                                    success = True
                                    file_queue.task_done()
                                    logger.info(f"Arquivo {json_filename} processado com sucesso")
                                    
                                except Exception as e:
                                    retry_count += 1
                                    if retry_count < app.config['MAX_RETRIES']:
                                        logger.warning(f"Tentativa {retry_count} falhou para arquivo {file_info.get('json_filename', 'unknown')}: {e}")
                                        time.sleep(app.config['RETRY_DELAY'])
                                    else:
                                        logger.error(f"Todas as tentativas falharam para arquivo {file_info.get('json_filename', 'unknown')}")
                                        # Adicionar à lista de falhas para retry posterior
                                        failed_files[user_id].append(file_info)
                                        file_queue.task_done()
                        
                    finally:
                        user_locks[user_id].release()
                else:
                    logger.warning(f"Timeout ao tentar obter lock para usuário {username}")
                    # Adicionar arquivos à lista de falhas
                    failed_files[user_id].extend(files)
                    for _ in files:
                        file_queue.task_done()
            
            except Exception as e:
                logger.error(f"Erro no processamento do usuário {username}: {e}")
                # Adicionar arquivos à lista de falhas
                failed_files[user_id].extend(files)
                for _ in files:
                    file_queue.task_done()
        
        # Tentar processar arquivos que falharam
        retry_failed_files()
        
    except Exception as e:
        logger.error(f"Erro no processamento do lote: {e}")
    
    logger.info(f"Finalizado processamento do lote com {len(users_batch)} usuários em {(datetime.now() - start_time).total_seconds()} segundos")

def process_file_queue():
    """Processa a fila de arquivos em background, agrupando por usuário e distribuindo entre threads."""
    user_batches = defaultdict(lambda: {'username': None, 'files': []})
    current_batch = {}
    batch_count = 0
    
    while True:
        try:
            # Coletar arquivos da fila
            while True:  # Loop infinito para processar todos os itens
                try:
                    file_info = file_queue.get(timeout=1)  # Timeout de 1 segundo
                    user_id = file_info['user_id']
                    username = file_info['username']
                    
                    # Inicializar dados do usuário se necessário
                    if user_id not in user_batches:
                        user_batches[user_id]['username'] = username
                    
                    # Adicionar arquivo ao lote do usuário
                    user_batches[user_id]['files'].append(file_info)
                    
                    # Se atingiu o tamanho do lote para este usuário
                    if len(user_batches[user_id]['files']) >= app.config['BATCH_SIZE']:
                        # Adicionar ao lote atual
                        current_batch[user_id] = user_batches[user_id]
                        user_batches[user_id] = {'username': username, 'files': []}
                        
                        # Se atingiu o número máximo de usuários por thread
                        if len(current_batch) >= app.config['USERS_PER_THREAD']:
                            # Submeter para processamento em thread separada
                            thread_pool.submit(process_user_batch, current_batch.copy())
                            current_batch = {}
                            batch_count += 1
                            logger.info(f"Submetido lote #{batch_count} para processamento")
                
                except Empty:  # Usando Empty ao invés de Queue.Empty
                    # Processar TODOS os lotes pendentes em user_batches
                    if user_batches:
                        # converte cada usuário em um lote próprio
                        for user_id, info in user_batches.items():
                            single_batch = { user_id: info }
                            thread_pool.submit(process_user_batch, single_batch)
                            batch_count += 1
                            logger.info(f"Submetido lote final #{batch_count} (user {user_id}) para processamento")
                        user_batches.clear()
                    
                    # Também limpa qualquer current_batch por precaução
                    if current_batch:
                        thread_pool.submit(process_user_batch, current_batch.copy())
                        batch_count += 1
                        logger.info(f"Submetido lote final #{batch_count} para processamento")
                        current_batch = {}
                    break
            
            # Pausa curta para evitar uso excessivo de CPU
            threading.Event().wait(0.1)  # 100ms
            
        except Exception as e:
            logger.error(f"Erro no processamento da fila: {e}")
            threading.Event().wait(1)

# Iniciar thread de processamento da fila
queue_processor = threading.Thread(target=process_file_queue, daemon=True)
queue_processor.start()

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

    # Gerar nome do arquivo JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f"api_data_{timestamp}_{uuid.uuid4().hex[:6]}.json"
    
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
            'sourceFile': json_filename
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
            'sourceFile': json_filename
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
            'sourceFile': json_filename
        }
        rows.append(row)

    return rows, user_id, username

def update_user_csv(user_id, username, new_data_rows, json_filename):
    """Atualiza ou cria o arquivo CSV para um usuário específico."""
    if not user_id or not username or not new_data_rows:
        logger.warning("Dados insuficientes para atualizar CSV (userId, username ou dados ausentes).")
        return

    output_folder = app.config['CSV_OUTPUT_FOLDER']
    csv_filename_base = f"{username}_{user_id}"
    csv_filename = sanitize_filename(csv_filename_base) + ".csv"
    output_path = output_folder / csv_filename

    logger.info(f"Preparando para atualizar CSV para usuário '{username}' ({user_id}) em {output_path}")
    logger.info(f"Número de linhas a processar: {len(new_data_rows)}")

    try:
        # Criar DataFrame apenas com os novos dados
        df_new = pd.DataFrame(new_data_rows)
        logger.info(f"DataFrame criado com {len(df_new)} linhas")
        
        # Adicionar coluna com nome do arquivo JSON
        df_new['sourceFile'] = json_filename

        # Garantir colunas e ordem
        expected_cols = [
            'userId', 'username', 'uploadTimestamp', 'eventType', 'actionType',
            'timestamp', 'correlationId', 'url', 'pageTitle', 'target_tagName',
            'target_selector', 'target_text', 'inputValue', 'keyPressed',
            'scrollX', 'scrollY', 'requestUrl', 'requestMethod',
            'requestStatusCode', 'requestId', 'sourceFile'
        ]
        for col in expected_cols:
            if col not in df_new.columns:
                df_new[col] = None
        df_new = df_new[expected_cols]

        # Lock para evitar condição de corrida
        with file_processing_lock:
            try:
                if output_path.exists():
                    logger.info(f"Lendo CSV existente: {output_path}")
                    try:
                        # Ler apenas as últimas 1000 linhas do CSV existente para melhor performance
                        df_existing = pd.read_csv(output_path, nrows=1000)
                        logger.info(f"CSV existente lido com {len(df_existing)} linhas")
                        
                        # Concatenar e ordenar
                        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
                        df_to_save = df_combined.sort_values(by='timestamp').reset_index(drop=True)
                        logger.info(f"Combinado {len(df_existing)} registros existentes com {len(df_new)} novos")
                    except pd.errors.EmptyDataError:
                        logger.warning(f"CSV existente {output_path} está vazio. Sobrescrevendo.")
                        df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)
                    except Exception as read_err:
                        logger.error(f"Erro ao ler CSV existente {output_path}: {read_err}. Tentando salvar apenas novos dados.")
                        df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)
                else:
                    logger.info(f"CSV não existente. Criando novo arquivo: {output_path}")
                    df_to_save = df_new.sort_values(by='timestamp').reset_index(drop=True)

                # Salvar
                if not df_to_save.empty:
                    # Salvar em chunks para melhor performance
                    chunk_size = 1000
                    total_rows = len(df_to_save)
                    
                    for i in range(0, total_rows, chunk_size):
                        chunk = df_to_save.iloc[i:i + chunk_size]
                        mode = 'w' if i == 0 else 'a'
                        header = i == 0
                        chunk.to_csv(output_path, mode=mode, header=header, index=False, encoding='utf-8')
                        logger.info(f"Salvando chunk {i//chunk_size + 1} de {(total_rows + chunk_size - 1)//chunk_size}")
                    
                    logger.info(f"CSV salvo com sucesso para {user_id} em {output_path}")
                else:
                    logger.warning(f"Nenhum dado para salvar para o usuário {user_id} após processamento.")

            except Exception as e:
                logger.error(f"Erro GERAL ao processar/salvar CSV para {user_id} em {output_path}: {e}")
                raise

    except Exception as e:
        logger.error(f"Erro ao processar dados para CSV: {e}")
        raise

def deep_decrypt_fields(data, decryption):
    """Percorre recursivamente o dicionário/lista e descriptografa campos 'encryptedData'."""
    if isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            if k == 'encryptedData' and isinstance(v, dict) and 'chunks' in v:
                try:
                    new_data = decryption.decrypt_data(v)
                except Exception as e:
                    new_data = {'decryptionError': str(e), 'original': v}
                return new_data  # substitui o próprio dicionário pelo conteúdo descriptografado
            else:
                new_data[k] = deep_decrypt_fields(v, decryption)
        return new_data
    elif isinstance(data, list):
        return [deep_decrypt_fields(item, decryption) for item in data]
    else:
        return data

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

        encrypted_data = request.get_json()
        if not encrypted_data:
            logger.warning("Dados JSON ausentes na requisição para /data")
            return jsonify({"error": "Dados JSON ausentes"}), 400

        # Gerar nome do arquivo JSON UMA ÚNICA VEZ
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"api_data_{timestamp}_{uuid.uuid4().hex[:6]}.json"

        # Decrypt the data
        try:
            if isinstance(encrypted_data, dict) and 'encryptedData' in encrypted_data:
                encrypted_data = encrypted_data['encryptedData']
            
            decrypted_data = decryption.decrypt_data(encrypted_data)
            decrypted_data = deep_decrypt_fields(decrypted_data, decryption)
        except Exception as decrypt_error:
            logger.error(f"Erro ao descriptografar dados: {str(decrypt_error)}")
            return jsonify({"error": "Erro ao descriptografar dados"}), 400

        # Extrair dados para CSV
        new_data_rows, user_id, username = extract_data_from_json(decrypted_data, json_filename)

        if user_id and username and new_data_rows:
            # Adicionar à fila de processamento
            file_info = {
                'user_id': user_id,
                'username': username,
                'json_filename': json_filename,
                'data_rows': new_data_rows
            }
            file_queue.put(file_info)
            logger.info(f"Dados adicionados à fila de processamento para usuário {user_id}")
        else:
            logger.warning("Não foi possível adicionar dados à fila devido a dados ausentes.")

        # Salvar o JSON descriptografado
        filepath = app.config['DATA_FOLDER'] / json_filename
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(decrypted_data, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON descriptografado salvo em {filepath}")
        except Exception as save_err:
            logger.error(f"Erro ao salvar JSON descriptografado {filepath}: {save_err}")

        # Resposta da API
        return jsonify({
            "success": True,
            "message": "Data received and processing started.",
            "batchId": uuid.uuid4().hex,
            "timestamp": datetime.now().isoformat(),
            "receivedItems": {
                "requests": len(decrypted_data.get('requests', [])),
                "userActions": len(decrypted_data.get('userActions', [])),
                "documentContents": len(decrypted_data.get('documentContents', [])),
                "profiles": len(decrypted_data.get('profiles', []))
            }
        }), 201

    except json.JSONDecodeError:
        logger.error("JSON inválido na requisição para /data")
        return jsonify({"error": "JSON inválido"}), 400
    except Exception as e:
        logger.exception(f"Erro inesperado ao processar requisição para /data")
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

@app.route('/data/<filename>', methods=['GET'])
@token_required
def get_json_data(filename):
    try:
        # Verificar se o arquivo existe
        filepath = app.config['DATA_FOLDER'] / filename
        if not filepath.exists():
            return jsonify({"error": "Arquivo não encontrado"}), 404

        # Ler o arquivo JSON
        with open(filepath, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)

        # Descriptografar os dados
        try:
            decrypted_data = decryption.decrypt_data(encrypted_data)
            return jsonify({
                "filename": filename,
                "data": decrypted_data,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as decrypt_error:
            logger.error(f"Erro ao descriptografar dados do arquivo {filename}: {str(decrypt_error)}")
            return jsonify({"error": "Erro ao descriptografar dados"}), 400

    except Exception as e:
        logger.exception(f"Erro ao processar arquivo {filename}")
        return jsonify({"error": "Erro interno ao processar arquivo"}), 500

@app.route('/data', methods=['GET'])
@token_required
def list_json_files():
    try:
        files = []
        for filename in os.listdir(app.config['DATA_FOLDER']):
            if filename.endswith('.json'):
                filepath = app.config['DATA_FOLDER'] / filename
                file_info = {
                    "filename": filename,
                    "size": os.path.getsize(filepath),
                    "created": datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
                    "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                }
                files.append(file_info)
        
        return jsonify({
            "files": files,
            "count": len(files),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.exception("Erro ao listar arquivos")
        return jsonify({"error": "Erro interno ao listar arquivos"}), 500

# --- Execução da API ---
if __name__ == '__main__':
    # Usar host='0.0.0.0' para ser acessível externamente
    # debug=True é útil para desenvolvimento, mas desative em produção
    app.run(host='0.0.0.0', port=5000, debug=False)