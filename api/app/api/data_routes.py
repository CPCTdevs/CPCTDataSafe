from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from dateutil import parser as dt_parser
import uuid
import json
from app.models.models import db, User, UserAction, Request, DocumentContent
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.config.config import logger
from utils.decryption import Decryption

data_bp = Blueprint('data', __name__)

def deep_decrypt_fields(data):
    """Decifra o payload, se vier criptografado com RSA (formato 'chunks')."""
    if not data:
        return None

    # Caso o payload completo esteja em chunks RSA
    if isinstance(data, dict) and 'chunks' in data:
        try:
            decrypted = Decryption().decrypt_payload(data)
            logger.info("Payload RSA descriptografado com sucesso")
            return decrypted
        except Exception as exc:
            logger.error(f"Falha ao descriptografar payload RSA: {exc}")
            return None

    # Sem criptografia adicional
    return data

def safe_parse_timestamp(value: str) -> datetime:
    """Tenta converter uma string em datetime usando dateutil. Se falhar, retorna datetime.utcnow()."""
    if not value:
        return datetime.utcnow()
    try:
        return dt_parser.isoparse(value)
    except Exception:
        logger.warning(f"Timestamp inválido recebido: {value}. Usando horário atual.")
        return datetime.utcnow()

@data_bp.route('/data', methods=['POST'])
@jwt_required()
def simple_save_data():
    try:
        logger.info("Recebida requisição para /data")
        user_info = get_jwt_identity()
        user = User.query.filter_by(username=user_info).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.get_json()
        if not data:
            logger.warning("Dados JSON ausentes na requisição para /data")
            return jsonify({"error": "Dados JSON ausentes"}), 400

        # LOG: Estrutura dos dados recebidos
        logger.info(f"Estrutura dos dados recebidos: {list(data.keys())}")
        
        # Processar dados sem descriptografia por enquanto
        decrypted_data = deep_decrypt_fields(data) or {}

        # Extrair dados do JSON
        user_id = user.id
        username = user.username
        upload_timestamp = datetime.utcnow()

        # LOG: Quantas userActions foram recebidas
        user_actions = decrypted_data.get('userActions', [])
        logger.info(f"Recebidas {len(user_actions)} userActions")

        # Salvar userActions se existirem
        for i, action in enumerate(user_actions):
            # LOG: Dados de cada action
            logger.info(f"UserAction {i+1}:")
            logger.info(f"  - type: {action.get('type')}")
            logger.info(f"  - timestamp: {action.get('timestamp')}")
            logger.info(f"  - correlationId: {action.get('correlationId')}")
            
            # LOG: pageContext
            page_context = action.get('pageContext', {})
            logger.info(f"  - pageContext: {page_context}")
            logger.info(f"    - url: {page_context.get('url')}")
            logger.info(f"    - title: {page_context.get('title')}")
            
            # LOG: target
            target = action.get('target', {})
            logger.info(f"  - target: {target}")
            logger.info(f"    - tagName: {target.get('tagName')}")
            logger.info(f"    - selector: {target.get('selector')}")
            logger.info(f"    - text: {target.get('text')}")
            
            # LOG: outros campos
            logger.info(f"  - value: {action.get('value')}")
            logger.info(f"  - key: {action.get('key')}")
            
            # LOG: scrollPosition
            scroll_position = action.get('scrollPosition', {})
            logger.info(f"  - scrollPosition: {scroll_position}")
            logger.info(f"    - x: {scroll_position.get('x')}")
            logger.info(f"    - y: {scroll_position.get('y')}")
            
            ua = UserAction(
                user_id=user.id,
                action_type=action.get('type'),
                timestamp=safe_parse_timestamp(action.get('timestamp')),
                correlation_id=action.get('correlationId'),
                url=action.get('pageContext', {}).get('url'),
                page_title=action.get('pageContext', {}).get('title'),
                target_tag_name=action.get('target', {}).get('tagName'),
                target_selector=action.get('target', {}).get('selector'),
                key_pressed=action.get('key'),
                scroll_x=action.get('scrollPosition', {}).get('x'),
                scroll_y=action.get('scrollPosition', {}).get('y'),
                source_file=None,
                upload_timestamp=upload_timestamp
            )
            
            # LOG: Valores que serão salvos no banco
            logger.info(f"  - Valores para salvar no banco:")
            logger.info(f"    - url: {ua.url}")
            logger.info(f"    - page_title: {ua.page_title}")
            logger.info(f"    - target_tag_name: {ua.target_tag_name}")
            logger.info(f"    - target_selector: {ua.target_selector}")
            logger.info(f"    - key_pressed: {ua.key_pressed}")
            logger.info(f"    - scroll_x: {ua.scroll_x}")
            logger.info(f"    - scroll_y: {ua.scroll_y}")
            
            # Usar os novos métodos para criptografar os dados sensíveis
            if action.get('target', {}).get('text'):
                ua.set_target_text(action.get('target', {}).get('text'))
                logger.info(f"    - target_text criptografado: {action.get('target', {}).get('text')}")
            else:
                logger.info(f"    - target_text: VAZIO")
                
            if action.get('value'):
                ua.set_input_value(action.get('value'))
                logger.info(f"    - input_value criptografado: {action.get('value')}")
            else:
                logger.info(f"    - input_value: VAZIO")
                
            db.session.add(ua)

        # Salvar requests se existirem
        requests_data = decrypted_data.get('requests', [])
        logger.info(f"Recebidas {len(requests_data)} requests")
        
        for req in requests_data:
            rq = Request(
                user_id=user.id,
                timestamp=safe_parse_timestamp(req.get('timestamp')),
                request_url=req.get('url'),
                request_method=req.get('method'),
                request_status_code=req.get('statusCode'),
                request_id=req.get('requestId'),
                source_file=None,
                upload_timestamp=upload_timestamp
            )
            db.session.add(rq)

        # Salvar documentContents se existirem
        doc_contents = decrypted_data.get('documentContents', [])
        logger.info(f"Recebidas {len(doc_contents)} documentContents")
        
        for content_item in doc_contents:
            dc = DocumentContent(
                user_id=user.id,
                type=content_item.get('type'),
                timestamp=safe_parse_timestamp(content_item.get('timestamp')),
                correlation_id=content_item.get('correlationId'),
                url=content_item.get('pageContext', {}).get('url'),
                page_title=content_item.get('pageContext', {}).get('title'),
                source_file=None,
                upload_timestamp=upload_timestamp
            )
            db.session.add(dc)

        db.session.commit()
        logger.info(f"Dados salvos no banco para usuário {username} (id={user.id})")

        return jsonify({
            "success": True,
            "message": "Data received and saved in database.",
            "batchId": uuid.uuid4().hex,
            "timestamp": datetime.now().isoformat(),
            "receivedItems": {
                "requests": len(decrypted_data.get('requests', [])),
                "userActions": len(decrypted_data.get('userActions', [])),
                "documentContents": len(decrypted_data.get('documentContents', []))
            }
        }), 201

    except Exception as e:
        logger.exception(f"Erro inesperado ao processar requisição para /data")
        return jsonify({"error": "Erro interno no processamento dos dados", "details": str(e)}), 500 