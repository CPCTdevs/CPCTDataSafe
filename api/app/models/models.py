from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import base64
from flask import current_app

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    approval_status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Campos para verificação de email
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    verification_token_expires = db.Column(db.DateTime)
    
    # Campos para 2FA
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.JSON)
    
    # Campos para criptografia
    fernet_key = db.Column(db.String(256))
    jwt_key = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def increment_login_attempts(self):
        self.login_attempts += 1
        if self.login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()
    
    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def get_fernet_key(self):
        return self.fernet_key

    def set_jwt_key(self, encrypted_key):
        self.jwt_key = encrypted_key

    def get_jwt_key(self):
        return self.jwt_key

    def get_fernet(self):
        """Get a Fernet instance for this user"""
        if not self.fernet_key:
            return None
        try:
            # A chave armazenada no banco está criptografada com a chave mestre.
            master_key = current_app.config.get('FERNET_KEY')
            if not master_key:
                return None
            master_fernet = Fernet(master_key.encode())
            # Descriptografa a chave específica do usuário
            decrypted_key = master_fernet.decrypt(self.fernet_key.encode())
            return Fernet(decrypted_key)
        except Exception:
            # Retorna None caso ocorra qualquer erro durante a descriptografia
            return None
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret for 2FA setup"""
        import pyotp
        import secrets
        secret = pyotp.random_base32()
        self.totp_secret = secret
        return secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code generation"""
        import pyotp
        if not self.totp_secret:
            return None
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="CPCT Auditor System"
        )
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        import pyotp
        if not self.totp_secret or not self.is_2fa_enabled:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)  # 30s window
    
    def generate_backup_codes(self):
        """Generate backup codes for 2FA"""
        import secrets
        codes = [secrets.token_hex(4) for _ in range(10)]
        self.backup_codes = codes
        db.session.commit()
        return codes
    
    def verify_backup_code(self, code):
        """Verify a backup code and remove it if valid"""
        if not self.backup_codes:
            return False
        if code in self.backup_codes:
            self.backup_codes.remove(code)
            db.session.commit()
            return True
        return False

class UserAction(db.Model):
    __tablename__ = 'user_actions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action_type = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime)
    correlation_id = db.Column(db.String(120))
    url = db.Column(db.String(512))
    page_title = db.Column(db.String(256))
    target_tag_name = db.Column(db.String(64))
    target_selector = db.Column(db.String(256))
    target_text = db.Column(db.LargeBinary)  # Criptografado
    input_value = db.Column(db.LargeBinary)  # Criptografado
    key_pressed = db.Column(db.String(32))
    scroll_x = db.Column(db.Integer)
    scroll_y = db.Column(db.Integer)
    source_file = db.Column(db.String(256))
    upload_timestamp = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('user_actions', lazy=True))

    def encrypt_data(self, data):
        """Encrypt data using the user's Fernet key"""
        if not data:
            return None
        try:
            fernet = self.user.get_fernet()
            if not fernet:
                return None
            return fernet.encrypt(data.encode())
        except Exception:
            return None

    def decrypt_data(self, data):
        """Decrypt data using the user's Fernet key"""
        if not data:
            return None
        try:
            fernet = self.user.get_fernet()
            if not fernet:
                return None
            return fernet.decrypt(data).decode()
        except Exception:
            return None

    @property
    def decrypted_target_text(self):
        """Get decrypted target_text"""
        return self.decrypt_data(self.target_text)

    @property
    def decrypted_input_value(self):
        """Get decrypted input_value"""
        return self.decrypt_data(self.input_value)

    def set_target_text(self, text):
        """Set encrypted target_text"""
        self.target_text = self.encrypt_data(text)

    def set_input_value(self, value):
        """Set encrypted input_value"""
        self.input_value = self.encrypt_data(value)

class Request(db.Model):
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime)
    request_url = db.Column(db.String(512))
    request_method = db.Column(db.String(16))
    request_status_code = db.Column(db.Integer)
    request_id = db.Column(db.String(120))
    source_file = db.Column(db.String(256))
    upload_timestamp = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('requests', lazy=True))

class DocumentContent(db.Model):
    __tablename__ = 'document_contents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime)
    correlation_id = db.Column(db.String(120))
    url = db.Column(db.String(512))
    page_title = db.Column(db.String(256))
    source_file = db.Column(db.String(256))
    upload_timestamp = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('document_contents', lazy=True)) 

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    auditor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # login, approve_user, reject_user, etc
    details = db.Column(db.Text, nullable=True)  # JSON com detalhes da ação
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='audit_logs_as_user')
    auditor = db.relationship('User', foreign_keys=[auditor_id], backref='audit_logs_as_auditor') 