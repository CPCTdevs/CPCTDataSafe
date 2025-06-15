#!/bin/bash

# Esperar o PostgreSQL iniciar
echo "Waiting for PostgreSQL to start..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL started"

# Inicializar o banco de dados
echo "Initializing database..."
flask init-db

# Iniciar o Gunicorn
echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 \
     --workers 4 \
     --threads 4 \
     --worker-class gthread \
     --timeout 120 \
     --max-requests 1000 \
     --max-requests-jitter 50 \
     --keep-alive 5 \
     --log-level info \
     "run:app" 