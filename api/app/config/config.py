import os
import logging
import secrets
from cryptography.fernet import Fernet
from base64 import b64encode
import re

# --- Configurações de Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api_server.log", mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info("Logging configured.")

def generate_secure_key():
    """Generate a secure random key"""
    return secrets.token_urlsafe(32)

def init_fernet_key():
    """Initialize or get the master Fernet key"""
    key = os.getenv('FERNET_KEY')
    if not key:
        key = Fernet.generate_key().decode()
        logger.info("Generated new Fernet key")
    return key

def init_jwt_key():
    """Initialize or get the JWT key"""
    key = os.getenv('JWT_SECRET_KEY')
    if not key:
        key = generate_secure_key()
        logger.warning("No JWT_SECRET_KEY found in environment. Generated new key. Please set this key in your environment.")
    return key

# --- Configurações da Aplicação ---
class Config:
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://dbuser9876:s3cr3T!9876@db:5432/cpctdb')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT Configuration
    JWT_SECRET_KEY = init_jwt_key()
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 horas em segundos
    JWT_ERROR_MESSAGE_KEY = 'error'
    
    # Fernet Configuration - Não inicializa aqui, será feito no create_app
    FERNET_KEY = None
    
    CORS_HEADERS = 'Content-Type'

    # Configuração do CORS
    CORS_CONFIG = {
        'supports_credentials': True,
        'resources': {
            r"/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
                "expose_headers": ["Content-Type", "X-API-Key"]
            }
        }
    } 

    # Configurações de Segurança
    SECURITY_CONFIG = {
        # Rate Limiting
        'RATE_LIMIT_ENABLED': True,
        'RATE_LIMIT_DEFAULT': '100/hour',  # Limite padrão de requisições
        'RATE_LIMIT_STORAGE_URL': 'memory://',  # Armazenamento em memória
        
        # Validação de Senha
        'PASSWORD_MIN_LENGTH': 12,
        'PASSWORD_REQUIRE_UPPER': True,
        'PASSWORD_REQUIRE_LOWER': True,
        'PASSWORD_REQUIRE_NUMBERS': True,
        'PASSWORD_REQUIRE_SPECIAL': True,
        'PASSWORD_PATTERN': r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',
        
        # Verificação de Email
        'EMAIL_VERIFICATION_ENABLED': True,
        'EMAIL_VERIFICATION_TOKEN_EXPIRES': 3600,  # 1 hora
        'EMAIL_VERIFICATION_SENDER': 'noreply@cpct.com',
        
        # Captcha
        'CAPTCHA_ENABLED': True,
        'CAPTCHA_LENGTH': 6,
        'CAPTCHA_EXPIRES': 300,  # 5 minutos
        
        # Domínios de Email Permitidos
        'ALLOWED_EMAIL_DOMAINS': [
            'cpct.com',
            'cpct.gov.br',
            'cpct.org.br',
            'gmail.com',
            'outlook.com',
            'hotmail.com',
            'yahoo.com',
            'usp.br',
            'unicamp.br',
            'unesp.br',
            'gov.br',
            'edu.br'
        ],
        'EMAIL_DOMAIN_VALIDATION_ENABLED': True  # Set to False to disable domain validation
    }

    # Funções de Validação
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Valida a força da senha"""
        if len(password) < Config.SECURITY_CONFIG['PASSWORD_MIN_LENGTH']:
            return False, f"A senha deve ter pelo menos {Config.SECURITY_CONFIG['PASSWORD_MIN_LENGTH']} caracteres"
        
        if Config.SECURITY_CONFIG['PASSWORD_REQUIRE_UPPER'] and not re.search(r'[A-Z]', password):
            return False, "A senha deve conter pelo menos uma letra maiúscula"
        
        if Config.SECURITY_CONFIG['PASSWORD_REQUIRE_LOWER'] and not re.search(r'[a-z]', password):
            return False, "A senha deve conter pelo menos uma letra minúscula"
        
        if Config.SECURITY_CONFIG['PASSWORD_REQUIRE_NUMBERS'] and not re.search(r'\d', password):
            return False, "A senha deve conter pelo menos um número"
        
        if Config.SECURITY_CONFIG['PASSWORD_REQUIRE_SPECIAL'] and not re.search(r'[@$!%*?&]', password):
            return False, "A senha deve conter pelo menos um caractere especial (@$!%*?&)"
        
        return True, "Senha válida"

    @staticmethod
    def validate_email_domain(email: str) -> bool:
        """Valida se o domínio do email está na lista de permitidos"""
        # Se a validação de domínio estiver desabilitada, aceita qualquer email válido
        if not Config.SECURITY_CONFIG.get('EMAIL_DOMAIN_VALIDATION_ENABLED', True):
            return '@' in email and '.' in email.split('@')[-1]
        
        domain = email.split('@')[-1].lower()
        allowed_domains = [d.lower() for d in Config.SECURITY_CONFIG['ALLOWED_EMAIL_DOMAINS']]
        return domain in allowed_domains 