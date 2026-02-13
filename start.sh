#!/bin/bash
# Production startup script for the IP whitelist application

set -e

# Initialize database
python -c "
import os
import database
from config import Config

# Ensure database directory exists
db_dir = os.path.dirname(Config.DATABASE_PATH)
if db_dir and not os.path.exists(db_dir):
    os.makedirs(db_dir, exist_ok=True)

# Initialize database
database.init_db()
"

# Get ports from environment (matching Config defaults)
INTERNAL_PORT=${INTERNAL_PORT:-8081}
MAIN_PORT=${MAIN_PORT:-8080}

# Function to cleanup background processes on exit
cleanup() {
    echo "Shutting down..."
    kill $INTERNAL_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start internal app in background with gunicorn
gunicorn \
    --bind 0.0.0.0:${INTERNAL_PORT} \
    --workers 1 \
    --threads 2 \
    --timeout 30 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:internal_app &
INTERNAL_PID=$!

# Start main app with gunicorn (foreground)
exec gunicorn \
    --bind 0.0.0.0:${MAIN_PORT} \
    --workers ${GUNICORN_WORKERS:-4} \
    --threads ${GUNICORN_THREADS:-2} \
    --timeout 30 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    --preload \
    app:main_app

