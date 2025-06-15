# CPCT Auditor System

Sistema de auditoria para o CPCT com recursos avançados de segurança.

## Requisitos

- Python 3.8+
- PostgreSQL 15+
- Docker e Docker Compose
- SMTP Server (para envio de emails)

## Configuração

1. Clone o repositório:
   ```bash
git clone https://github.com/seu-usuario/CPCTextension.git
cd CPCTextension
   ```

2. Configure as variáveis de ambiente:
```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

3. Inicie os containers:
   ```bash
docker-compose up -d
```

## Funcionalidades de Segurança

### Registro de Usuários
- Validação de força de senha
- Verificação de email
- Captcha para prevenção de bots
- Rate limiting para prevenção de ataques de força bruta
- Validação de domínios de email permitidos

### Autenticação
- Autenticação de dois fatores (2FA)
- Códigos de backup para 2FA
- Bloqueio de conta após tentativas falhas
- Tokens JWT para sessões
- Criptografia de chaves com Fernet

### Auditoria
- Registro de todas as ações
- Log de tentativas de login
- Registro de IP e user agent
- Histórico de alterações

## Rotas da API

### Autenticação
- POST `/api/v1/auth/register` - Registro de usuário
- POST `/api/v1/auth/login` - Login
- GET `/api/v1/auth/verify-email/<token>` - Verificação de email
- POST `/api/v1/auth/2fa/setup` - Configuração de 2FA
- POST `/api/v1/auth/2fa/verify` - Verificação de 2FA

### Usuários
- GET `/api/v1/users/me` - Informações do usuário atual
- PUT `/api/v1/users/me` - Atualização de dados
- GET `/api/v1/users/pending` - Lista de usuários pendentes (apenas auditores)

### Auditoria
- GET `/api/v1/audit/logs` - Logs de auditoria
- GET `/api/v1/audit/actions` - Ações registradas

## Desenvolvimento

### Estrutura do Projeto
```
CPCTextension/
├── app/
│   ├── api/
│   ├── models/
│   ├── utils/
│   └── static/
├── data/
├── keys/
├── ssl/
├── user_csvs/
├── docker-compose.yml
├── Dockerfile
├── nginx.conf
└── requirements.txt
```

### Testes
```bash
# Executar testes
python -m pytest

# Executar testes com cobertura
python -m pytest --cov=app
```

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Crie um Pull Request

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes. 