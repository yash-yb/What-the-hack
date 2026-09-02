#!/usr/bin/env bash
# Create the backend virtualenv, install dependencies, run migrations, and seed demo users.
# Usage: ./deployment/scripts/bootstrap_backend.sh   (PostgreSQL must be running: docker compose up -d db)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
.venv/bin/alembic upgrade head
PYTHONPATH=. .venv/bin/python scripts/seed_demo_users.py
echo "Backend ready. Start it with: cd backend && PYTHONPATH=..:. .venv/bin/uvicorn app.main:app --reload"
