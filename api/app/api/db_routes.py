from flask import Blueprint, jsonify, request, make_response
from sqlalchemy import inspect, text, or_
from app.models.models import db, User, UserAction, Request, DocumentContent, AuditLog
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.config.config import logger
import csv
import io
from datetime import datetime

db_bp = Blueprint('db', __name__)

@db_bp.route('/api/v1/databases', methods=['GET'])
@jwt_required()
def list_databases():
    """Endpoint para listar todos os bancos de dados disponíveis"""
    try:
        # Obtém a conexão do SQLAlchemy
        engine = db.engine
        
        # Lista todos os bancos de dados
        with engine.connect() as conn:
            result = conn.execute(text("SELECT datname FROM pg_database WHERE datistemplate = false;"))
            databases = [row[0] for row in result]
            
        return jsonify({
            'databases': databases,
            'count': len(databases)
        }), 200
    except Exception as e:
        logger.error(f"Erro ao listar bancos de dados: {str(e)}")
        return jsonify({
            'error': 'Erro ao listar bancos de dados',
            'details': str(e)
        }), 500

@db_bp.route('/api/v1/tables', methods=['GET'])
@jwt_required()
def list_tables():
    """Endpoint para listar todas as tabelas do banco atual"""
    try:
        # Obtém o inspetor do SQLAlchemy
        inspector = inspect(db.engine)
        
        # Lista todas as tabelas
        tables = inspector.get_table_names()
        
        # Para cada tabela, obtém informações sobre suas colunas
        table_info = {}
        for table in tables:
            columns = inspector.get_columns(table)
            table_info[table] = [{
                'name': col['name'],
                'type': str(col['type']),
                'nullable': col.get('nullable', True),
                'default': str(col.get('default', '')),
                'primary_key': col.get('primary_key', False)
            } for col in columns]
            
        return jsonify({
            'tables': table_info,
            'count': len(tables)
        }), 200
    except Exception as e:
        logger.error(f"Erro ao listar tabelas: {str(e)}")
        return jsonify({
            'error': 'Erro ao listar tabelas',
            'details': str(e)
        }), 500

@db_bp.route('/api/v1/tables/<table_name>', methods=['GET'])
@jwt_required()
def get_table_data(table_name):
    """Endpoint para obter dados de uma tabela específica"""
    try:
        # Verifica se a tabela existe
        inspector = inspect(db.engine)
        if table_name not in inspector.get_table_names():
            return jsonify({
                'error': f'Tabela {table_name} não encontrada'
            }), 404
            
        # Obtém os dados da tabela
        with db.engine.connect() as conn:
            result = conn.execute(text(f"SELECT * FROM {table_name} LIMIT 1000;"))
            columns = result.keys()
            data = [dict(zip(columns, row)) for row in result]
            
        return jsonify({
            'table': table_name,
            'columns': columns,
            'data': data,
            'count': len(data)
        }), 200
    except Exception as e:
        logger.error(f"Erro ao obter dados da tabela {table_name}: {str(e)}")
        return jsonify({
            'error': f'Erro ao obter dados da tabela {table_name}',
            'details': str(e)
        }), 500

@db_bp.route('/export-user-data/<int:user_id>', methods=['GET'])
@jwt_required(optional=True)
def export_user_data(user_id):
    """Exporta dados de um usuário específico como CSV"""
    try:
        # Verificar token via header ou query parameter
        current_user_identity = get_jwt_identity()
        
        if not current_user_identity:
            # Se não tem token no header, verificar query parameter
            token = request.args.get('token')
            if token:
                from flask_jwt_extended import decode_token
                try:
                    decoded_token = decode_token(token)
                    current_user_identity = decoded_token['sub']
                except Exception as e:
                    logger.error(f"Erro ao decodificar token: {str(e)}")
                    return jsonify({'error': 'Token inválido'}), 401
            else:
                return jsonify({'error': 'Token de autorização requerido'}), 401
        
        current_user = User.query.filter_by(username=current_user_identity).first()
        if not current_user or current_user.role not in ['admin', 'auditor']:
            return jsonify({'error': 'Acesso negado'}), 403

        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'Usuário não encontrado'}), 404

        data_type = request.args.get('type', 'all')  # all, user_actions, requests, document_contents
        
        if data_type in ['all', 'user_actions']:
            # Exportar User Actions
            user_actions = UserAction.query.filter_by(user_id=user_id).all()
            if user_actions:
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Headers
                writer.writerow([
                    'ID', 'Action Type', 'Timestamp', 'Correlation ID', 'URL', 'Page Title',
                    'Target Tag', 'Target Selector', 'Target Text', 'Input Value', 'Key Pressed',
                    'Scroll X', 'Scroll Y', 'Upload Timestamp'
                ])
                
                # Data
                for action in user_actions:
                    writer.writerow([
                        action.id,
                        action.action_type,
                        action.timestamp,
                        action.correlation_id,
                        action.url,
                        action.page_title,
                        action.target_tag_name,
                        action.target_selector,
                        action.decrypted_target_text,  # Descriptografado
                        action.decrypted_input_value,  # Descriptografado
                        action.key_pressed,
                        action.scroll_x,
                        action.scroll_y,
                        action.upload_timestamp
                    ])
                
                response = make_response(output.getvalue())
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=user_actions_{target_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                return response

        if data_type in ['all', 'requests']:
            # Exportar Requests
            requests = Request.query.filter_by(user_id=user_id).all()
            if requests:
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Headers
                writer.writerow([
                    'ID', 'Timestamp', 'URL', 'Method', 'Status Code', 'Request ID', 'Upload Timestamp'
                ])
                
                # Data
                for req in requests:
                    writer.writerow([
                        req.id,
                        req.timestamp,
                        req.request_url,
                        req.request_method,
                        req.request_status_code,
                        req.request_id,
                        req.upload_timestamp
                    ])
                
                response = make_response(output.getvalue())
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=requests_{target_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                return response

        if data_type in ['all', 'document_contents']:
            # Exportar Document Contents
            documents = DocumentContent.query.filter_by(user_id=user_id).all()
            if documents:
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Headers
                writer.writerow([
                    'ID', 'Type', 'Timestamp', 'Correlation ID', 'URL', 'Page Title', 'Upload Timestamp'
                ])
                
                # Data
                for doc in documents:
                    writer.writerow([
                        doc.id,
                        doc.type,
                        doc.timestamp,
                        doc.correlation_id,
                        doc.url,
                        doc.page_title,
                        doc.upload_timestamp
                    ])
                
                response = make_response(output.getvalue())
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=document_contents_{target_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                return response

        return jsonify({'error': 'Nenhum dado encontrado para exportar'}), 404

    except Exception as e:
        logger.error(f"Erro ao exportar dados do usuário {user_id}: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@db_bp.route('/users-summary', methods=['GET'])
@jwt_required()
def users_summary():
    """Retorna resumo dos dados de todos os usuários"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role not in ['admin', 'auditor']:
            return jsonify({'error': 'Acesso negado'}), 403

        users = User.query.all()
        summary = []

        for user in users:
            user_actions_count = UserAction.query.filter_by(user_id=user.id).count()
            requests_count = Request.query.filter_by(user_id=user.id).count()
            documents_count = DocumentContent.query.filter_by(user_id=user.id).count()

            summary.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'approval_status': user.approval_status,
                'is_2fa_enabled': user.is_2fa_enabled,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'data_counts': {
                    'user_actions': user_actions_count,
                    'requests': requests_count,
                    'document_contents': documents_count,
                    'total': user_actions_count + requests_count + documents_count
                }
            })

        return jsonify({'users': summary}), 200

    except Exception as e:
        logger.error(f"Erro ao obter resumo dos usuários: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@db_bp.route('/delete-user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_and_data(user_id):
    """Exclui completamente um usuário e todos os seus dados"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role not in ['admin', 'auditor']:
            return jsonify({'error': 'Acesso negado'}), 403

        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'Usuário não encontrado'}), 404

        # Deletar dados relacionados primeiro para evitar conflitos de FK
        deleted_actions = UserAction.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        deleted_requests = Request.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        deleted_docs = DocumentContent.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        deleted_audit = AuditLog.query.filter(or_(AuditLog.user_id == user_id, AuditLog.auditor_id == user_id)).delete(synchronize_session=False)

        # Finalmente, deletar o próprio usuário
        db.session.delete(target_user)
        db.session.commit()

        logger.info(
            f"Usuário {target_user.username} (id={user_id}) removido. "
            f"Actions: {deleted_actions}, Requests: {deleted_requests}, "
            f"Docs: {deleted_docs}, AuditLogs: {deleted_audit}"
        )

        return jsonify({
            'success': True,
            'message': f'Dados do usuário {target_user.username} excluídos com sucesso',
            'deletedCounts': {
                'user_actions': deleted_actions,
                'requests': deleted_requests,
                'document_contents': deleted_docs,
                'audit_logs': deleted_audit
            }
        }), 200

    except Exception as e:
        logger.error(f"Erro ao excluir dados do usuário {user_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Erro interno do servidor'}), 500 