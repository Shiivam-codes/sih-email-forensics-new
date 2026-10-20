#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

trap 'kill 0' EXIT INT TERM

.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload &
(
  cd frontend
  npm run dev -- --host 127.0.0.1 --port 5173
) &

wait
