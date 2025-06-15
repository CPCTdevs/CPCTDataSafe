from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models.models import db, User, AuditLog
from app.config.config import logger, generate_secure_key, Config
from app.utils.audit import AuditLogger
from datetime import datetime
from datetime import timedelta
from cryptography.fernet import Fernet
import base64
import pyotp
import qrcode
import io
import json
import secrets
import string
import hashlib
from utils.decryption import Decryption
from pathlib import Path

auth_bp = Blueprint('auth', __name__)

def encrypt_user_key(user_key):
    """Encrypt a user's Fernet key with the master key"""
    master_fernet = Fernet(current_app.config['FERNET_KEY'].encode())
    return master_fernet.encrypt(user_key).decode()

def decrypt_client_data(encrypted_data, client_key_hash):
    """
    Descriptografar dados sensíveis enviados do cliente
    Por segurança, vamos simular a descriptografia e permitir
    que o servidor continue funcionando normalmente
    """
    if not isinstance(encrypted_data, dict):
        return encrypted_data
    
    decrypted = encrypted_data.copy()
    
    # Lista de campos que podem estar criptografados
    sensitive_fields = ['password', 'totp_token', 'backup_code']
    
    for field in sensitive_fields:
        # Verificar se o campo foi marcado como criptografado
        if f'{field}_encrypted' in decrypted and decrypted.get(f'{field}_encrypted'):
            encrypted_value = decrypted.get(field)
            if encrypted_value:
                try:
                    # Por enquanto, vamos assumir que a descriptografia foi bem-sucedida
                    # Em uma implementação real, você usaria a chave do cliente para descriptografar
                    # 
                    # Implementação simplificada: remover indicadores de criptografia
                    # e manter o valor original (que na verdade está criptografado)
                    # 
                    # NOTA: Isto é apenas para demonstração. Em produção real,
                    # você implementaria a descriptografia AES adequada.
                    
                    logger.info(f"Campo {field} foi recebido criptografado do cliente")
                    
                    # Por segurança, vamos retornar um erro se dados chegarem criptografados
                    # até implementarmos a descriptografia completa
                    return None
                    
                except Exception as e:
                    logger.error(f"Erro ao descriptografar campo {field}: {str(e)}")
                    return None
            
            # Remover marcadores de criptografia
            del decrypted[f'{field}_encrypted']
    
    # Remover hash da chave do cliente
    if '_client_key_hash' in decrypted:
        del decrypted['_client_key_hash']
    
    return decrypted

def process_request_data():
    """Processar dados da requisição, descriptografando se necessário"""
    try:
        data = request.get_json()
        if not data:
            return None
        
        # Detectar payload RSA (chunks)
        if 'chunks' in data:
            try:
                decrypted = Decryption().decrypt_payload(data)
                logger.info("Payload descriptografado com sucesso (RSA)")
                return decrypted
            except Exception as e:
                logger.error(f"Falha ao descriptografar payload RSA: {str(e)}")
                return None

        # Detectar criptografia client-side AES (client_key_hash)
        if data.get('_client_key_hash'):
            logger.warning("Payload AES client-side recebido, recurso ainda não suportado")
            return None

        return data
        
    except Exception as e:
        logger.error(f"Erro ao processar dados da requisição: {str(e)}")
        return None

def generate_captcha():
    """Gera um captcha simples"""
    if not current_app.config.get('SECURITY_CONFIG', {}).get('CAPTCHA_ENABLED', False):
        return None
    
    length = current_app.config.get('SECURITY_CONFIG', {}).get('CAPTCHA_LENGTH', 6)
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def send_verification_email(user):
    """Simula envio de email de verificação"""
    # Por enquanto, apenas logar a ação
    logger.info(f"Email de verificação enviado para {user.email}")

@auth_bp.route('/register', methods=['POST'])
def register():
    """Registra um novo usuário"""
    try:
        # Processar dados da requisição (descriptografar se necessário)
        data = process_request_data()
        
        if data is None:
            return jsonify({'error': 'Dados da requisição inválidos ou criptografia não suportada ainda'}), 400
        
        # Validação dos campos obrigatórios
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Campo {field} é obrigatório'}), 400
        
        # Validação do domínio do email
        if not Config.validate_email_domain(data['email']):
            return jsonify({'error': 'Domínio de email não permitido'}), 400
        
        # Validação da força da senha
        is_valid, message = Config.validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Verifica se o usuário já existe
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Nome de usuário já existe'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email já registrado'}), 400
        
        # Define o papel: por padrão 'user'. Painel /admin pode enviar role='auditor'.
        requested_role = data.get('role', 'user')
        role = 'auditor' if requested_role == 'auditor' else 'user'

        user = User(
            username=data['username'],
            email=data['email'],
            role=role,
            approval_status='pending'
        )
        user.set_password(data['password'])
        
        # Gera e armazena a chave Fernet do usuário
        user_key = Fernet.generate_key()
        user.fernet_key = encrypt_user_key(user_key)
        
        # Gera e armazena a chave JWT do usuário
        jwt_key = generate_secure_key()
        user.set_jwt_key(encrypt_user_key(jwt_key.encode()))
        
        db.session.add(user)
        db.session.commit()
    
        # Simula envio de email de verificação
        send_verification_email(user)
        
        # Registra a ação
        AuditLogger.log_registration(user.id, True)
        
        return jsonify({
            'message': 'Auditor registrado com sucesso. Aguardando aprovação.',
            'requires_verification': False  # Temporariamente desabilitado
        }), 201
        
    except Exception as e:
        logger.error(f"Erro no registro: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verifica o email do usuário"""
    try:
        user = User.query.filter_by(verification_token=token).first()
        if not user:
            return jsonify({'error': 'Token inválido'}), 400
        
        if user.verification_token_expires and user.verification_token_expires < datetime.utcnow():
            return jsonify({'error': 'Token expirado'}), 400
        
        user.email_verified = True
        user.verification_token = None
        user.verification_token_expires = None
        db.session.commit()
        
        AuditLogger.log_email_verification(user.id, True)
        
        return jsonify({'message': 'Email verificado com sucesso'}), 200
        
    except Exception as e:
        logger.error(f"Erro na verificação de email: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        logger.info("Recebida requisição de login")
        
        # Processar dados da requisição (descriptografar se necessário)
        data = process_request_data()
        
        if data is None:
            return jsonify({'error': 'Dados da requisição inválidos. Por favor, desabilite a criptografia temporariamente.'}), 400
        
        username = data.get('username')
        password = data.get('password')
        totp_token = data.get('totp_token')
        backup_code = data.get('backup_code')
        
        if not username or not password:
            logger.warning("Login falhou: username ou password ausentes")
            return jsonify({'error': 'username e password são obrigatórios'}), 400
            
        user = User.query.filter_by(username=username).first()
        if not user:
            logger.warning(f"Login falhou: usuário {username} não encontrado")
            AuditLogger.log_login_attempt(None, False, {"reason": "user_not_found", "username": username})
            return jsonify({'error': 'Usuário ou senha inválidos'}), 401
        
        # Check if account is locked
        if user.is_locked():
            AuditLogger.log_login_attempt(user.id, False, {"reason": "account_locked"})
            return jsonify({'error': 'Conta bloqueada. Tente novamente mais tarde.'}), 423
            
        if not user.check_password(password):
            logger.warning(f"Login falhou: senha inválida para usuário {username}")
            user.increment_login_attempts()
            AuditLogger.log_login_attempt(user.id, False, {"reason": "invalid_password"})
            return jsonify({'error': 'Usuário ou senha inválidos'}), 401

        if user.approval_status != 'approved':
            AuditLogger.log_login_attempt(user.id, False, {"reason": "not_approved"})
            return jsonify({'error': 'Usuário ainda não foi aprovado'}), 403
            
        # 2FA é exigido apenas para usuários com papel 'auditor'
        if user.role == 'auditor':
            # Check 2FA - OBRIGATÓRIO após primeiro login (apenas auditor)
            if user.is_2fa_enabled:
                if not totp_token and not backup_code:
                    return jsonify({
                        'error': '2FA requerido',
                        'requires_2fa': True
                    }), 200

                # Verify TOTP ou backup code
                if totp_token:
                    if not user.verify_totp(totp_token):
                        AuditLogger.log_2fa_attempt(user.id, False, "totp")
                        return jsonify({'error': 'Código 2FA inválido'}), 401
                    AuditLogger.log_2fa_attempt(user.id, True, "totp")
                elif backup_code:
                    if not user.verify_backup_code(backup_code):
                        AuditLogger.log_2fa_attempt(user.id, False, "backup_code")
                        return jsonify({'error': 'Código de backup inválido'}), 401
                    AuditLogger.log_2fa_attempt(user.id, True, "backup_code")
            else:
                # 2FA NÃO CONFIGURADO - auditor deve configurar
                if user.last_login is None:
                    # Primeiro login - permitir mas marcar para configurar 2FA
                    pass
                else:
                    # Login subsequente sem 2FA - BLOQUEAR
                    AuditLogger.log_login_attempt(user.id, False, {"reason": "2fa_required_not_configured"})
                    return jsonify({
                        'error': '2FA é obrigatório. Configure a autenticação de dois fatores.',
                        'requires_2fa_setup': True
                    }), 403
        else:
            pass
        
        # Reset login attempts on successful login
        user.reset_login_attempts()
        user.last_login = datetime.utcnow()
        user.last_login_ip = AuditLogger.get_client_ip()
        db.session.commit()
        
        user_claims = {'id': user.id, 'role': user.role}
        access_token = create_access_token(identity=user.username, additional_claims=user_claims)
        
        response_data = {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'is_2fa_enabled': user.is_2fa_enabled,
                'first_login': user.last_login is None or not user.is_2fa_enabled
            }
        }
        
        # Se é primeiro login, indicar que 2FA deve ser configurado
        if user.role == 'auditor' and not user.is_2fa_enabled:
            response_data['requires_2fa_setup'] = True
            response_data['message'] = 'Login realizado. 2FA deve ser configurado obrigatoriamente.'
        
        AuditLogger.log_login_attempt(user.id, True, {"user_agent": request.headers.get('User-Agent')})
        logger.info(f"Login bem-sucedido para usuário {username}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/setup-2fa', methods=['POST'])
@jwt_required()
def setup_2fa():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Generate TOTP secret
        secret = current_user.generate_totp_secret()
        db.session.commit()
        
        # Generate QR code
        qr_uri = current_user.get_totp_uri()
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        import base64
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Log success without causing transaction issues
        try:
            AuditLogger.log_2fa_setup(current_user.id, True)
        except Exception as audit_error:
            logger.warning(f"Falha ao registrar log de auditoria: {str(audit_error)}")
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'manual_entry_key': secret,
            'account_name': current_user.email,
            'issuer': 'CPCT Auditor System'
        }), 200
    except Exception as e:
        logger.error(f"Erro ao configurar 2FA: {str(e)}")
        # Log failure without causing transaction issues
        try:
            current_user_id = User.query.filter_by(username=get_jwt_identity()).first().id
            AuditLogger.log_2fa_setup(current_user_id, False)
        except Exception as audit_error:
            logger.warning(f"Falha ao registrar log de auditoria: {str(audit_error)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/verify-2fa-setup', methods=['POST'])
@jwt_required()
def verify_2fa_setup():
    try:
        data = request.get_json()
        if not data or 'totp_token' not in data:
            return jsonify({'error': 'Código TOTP é obrigatório'}), 400
        
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        if not current_user.totp_secret:
            return jsonify({'error': '2FA não foi configurado ainda. Execute /setup-2fa primeiro'}), 400
        
        # Verify TOTP token
        if not current_user.verify_totp(data['totp_token']):
            AuditLogger.log_2fa_verification(current_user.id, False)
            return jsonify({'error': 'Código TOTP inválido'}), 401
        
        # Enable 2FA and generate backup codes
        current_user.is_2fa_enabled = True
        backup_codes = current_user.generate_backup_codes()
        db.session.commit()
        
        AuditLogger.log_2fa_verification(current_user.id, True)
        
        return jsonify({
            'message': '2FA ativado com sucesso',
            'backup_codes': backup_codes,
            'warning': 'Salve estes códigos de backup em um local seguro. Eles serão exibidos apenas uma vez.'
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao verificar 2FA: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/disable-2fa', methods=['POST'])
@jwt_required()
def disable_2fa():
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({'error': 'Senha é obrigatória para desabilitar 2FA'}), 400
        
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        if not current_user.check_password(data['password']):
            return jsonify({'error': 'Senha inválida'}), 401
        
        # Disable 2FA
        current_user.is_2fa_enabled = False
        current_user.totp_secret = None
        current_user.backup_codes = None
        db.session.commit()
        
        AuditLogger.log_action("2fa_disabled", user_id=current_user.id, success=True)
        
        return jsonify({'message': '2FA desabilitado com sucesso'}), 200
        
    except Exception as e:
        logger.error(f"Erro ao desabilitar 2FA: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

# === ROTAS PARA GESTÃO DE USUÁRIOS ===

@auth_bp.route('/users/pending', methods=['GET'])
@jwt_required()
def get_pending_users():
    """Lista usuários pendentes de aprovação"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role != 'auditor':
            return jsonify({'error': 'Acesso negado. Apenas auditores podem aprovar usuários.'}), 403
        
        # Buscar usuários pendentes
        pending_users = User.query.filter_by(approval_status='pending').all()
        
        users_data = []
        for user in pending_users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login_ip': user.last_login_ip,
                'email_verified': user.email_verified
            })
        
        return jsonify({
            'pending_users': users_data,
            'count': len(users_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao buscar usuários pendentes: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@jwt_required()
def approve_user(user_id):
    """Aprova um usuário pendente"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role != 'auditor':
            return jsonify({'error': 'Acesso negado. Apenas auditores podem aprovar usuários.'}), 403
        
        user_to_approve = User.query.get(user_id)
        if not user_to_approve:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        if user_to_approve.approval_status != 'pending':
            return jsonify({'error': 'Usuário já foi processado'}), 400
        
        # Aprovar usuário
        user_to_approve.approval_status = 'approved'
        db.session.commit()
        
        # Log da aprovação
        AuditLogger.log_user_approval(user_to_approve.id, current_user.id, True)
        
        return jsonify({
            'message': f'Usuário {user_to_approve.username} aprovado com sucesso',
            'user': {
                'id': user_to_approve.id,
                'username': user_to_approve.username,
                'email': user_to_approve.email,
                'approval_status': user_to_approve.approval_status
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao aprovar usuário: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/users/<int:user_id>/reject', methods=['POST'])
@jwt_required()
def reject_user(user_id):
    """Rejeita um usuário pendente"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role != 'auditor':
            return jsonify({'error': 'Acesso negado. Apenas auditores podem rejeitar usuários.'}), 403
        
        data = request.get_json() or {}
        reason = data.get('reason', 'Sem motivo especificado')
        
        user_to_reject = User.query.get(user_id)
        if not user_to_reject:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        if user_to_reject.approval_status != 'pending':
            return jsonify({'error': 'Usuário já foi processado'}), 400
        
        # Rejeitar usuário
        user_to_reject.approval_status = 'rejected'
        db.session.commit()
        
        # Log da rejeição
        AuditLogger.log_action(
            action="user_rejected",
            user_id=user_to_reject.id,
            auditor_id=current_user.id,
            details={"reason": reason},
            success=True
        )
        
        return jsonify({
            'message': f'Usuário {user_to_reject.username} rejeitado',
            'user': {
                'id': user_to_reject.id,
                'username': user_to_reject.username,
                'email': user_to_reject.email,
                'approval_status': user_to_reject.approval_status
            },
            'reason': reason
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao rejeitar usuário: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Obtém logs de auditoria com filtros"""
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user or current_user.role != 'auditor':
            return jsonify({'error': 'Acesso negado. Apenas auditores podem ver logs.'}), 403
        
        # Parâmetros de consulta
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        action_filter = request.args.get('action')
        user_filter = request.args.get('user_id')
        success_filter = request.args.get('success')
        
        # Query base
        query = db.session.query(AuditLog).join(User, AuditLog.user_id == User.id, isouter=True)
        
        # Filtros
        if action_filter:
            query = query.filter(AuditLog.action == action_filter)
        if user_filter:
            query = query.filter(AuditLog.user_id == int(user_filter))
        if success_filter is not None:
            query = query.filter(AuditLog.success == (success_filter.lower() == 'true'))
        
        # Ordenação e paginação
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Executar query com paginação
        total = query.count()
        logs = query.offset((page - 1) * per_page).limit(per_page).all()
        
        logs_data = []
        for log in logs:
            user = User.query.get(log.user_id) if log.user_id else None
            auditor = User.query.get(log.auditor_id) if log.auditor_id else None
            
            logs_data.append({
                'id': log.id,
                'action': log.action,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'success': log.success,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'details': log.details,
                'user': {
                    'id': user.id,
                    'username': user.username
                } if user else None,
                'auditor': {
                    'id': auditor.id,
                    'username': auditor.username
                } if auditor else None
            })
        
        return jsonify({
            'logs': logs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs de auditoria: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/public-key', methods=['GET'])
def get_public_key():
    """Retorna a chave pública RSA em formato PEM."""
    try:
        key_path = Path(__file__).resolve().parent.parent.parent / "keys" / "rsa_public.pem"
        if not key_path.exists():
            return jsonify({"error": "Chave pública não encontrada"}), 500
            
        with open(key_path, "rb") as f:
            pem_data = f.read()
            # Retorna PEM como string base64 para evitar problemas de encoding
            return jsonify({
                "key": base64.b64encode(pem_data).decode(),
                "format": "PEM",
                "encoding": "base64"
            }), 200
    except Exception as e:
        logger.error(f"Erro ao servir chave pública: {str(e)}")
        return jsonify({"error": "Erro interno ao obter chave pública"}), 500