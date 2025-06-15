from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from cryptography.fernet import Fernet
import secrets

from app.config.config import Config, logger, init_fernet_key
from app.models.models import db
from app.api.auth_routes import auth_bp
from app.api.data_routes import data_bp
from app.api.db_routes import db_bp
from app.api.health_routes import health_bp

def create_app():
    app = Flask(__name__)
    
    # Configura a chave JWT primeiro, antes de qualquer outra configuração
    jwt_secret = secrets.token_urlsafe(32)
    app.config['JWT_SECRET_KEY'] = jwt_secret
    app.config['SECRET_KEY'] = jwt_secret
    logger.info("JWT secret key configured")
    
    # Carrega as outras configurações
    app.config.from_object(Config)
    
    # Inicializa o JWT antes de qualquer outra extensão
    jwt = JWTManager(app)
    logger.info("JWT initialized successfully")
    
    # Inicializa o CORS
    CORS(app, **Config.CORS_CONFIG)
    
    # Inicializa o banco de dados
    db.init_app(app)
    
    # Inicializa a chave Fernet (apenas uma vez)
    if not app.config.get('FERNET_KEY'):
        app.config['FERNET_KEY'] = init_fernet_key()
    fernet = Fernet(app.config['FERNET_KEY'].encode())
    logger.info("Fernet object initialized successfully")
    
    # Registra os blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(data_bp)
    app.register_blueprint(db_bp, url_prefix='/api/v1')
    app.register_blueprint(health_bp)
    
    # Comando para criar as tabelas do banco
    @app.cli.command('init-db')
    def init_db():
        db.create_all()
        print('Banco de dados inicializado.')
    
    return app 