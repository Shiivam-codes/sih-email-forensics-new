PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: setup backend-install frontend-install backend frontend dev test lint format build clean data geoip sample-data warm-cache eval eval-corpus

setup: backend-install frontend-install

backend-install:
	python3.12 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt

frontend-install:
	cd frontend && npm install

backend:
	$(PY) -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

frontend:
	cd frontend && npm run dev -- --host 127.0.0.1 --port 5173

dev:
	./scripts/dev.sh

test:
	cd backend && ../$(PY) -m pytest

lint:
	$(PY) -m ruff check backend/app backend/tests scripts evaluation
	cd frontend && npm run build

format:
	$(PY) -m ruff format backend/app backend/tests

build:
	cd frontend && npm run build

data:
	./scripts/fetch_datasets.sh

geoip:
	./scripts/fetch_geoip.sh

sample-data:
	$(PY) scripts/sample_corpus.py

warm-cache:
	PYTHONPATH=backend $(PY) scripts/warm_cache.py

eval:
	PYTHONPATH=backend $(PY) evaluation/run_eval.py

eval-corpus:
	PYTHONPATH=backend $(PY) evaluation/run_eval.py --include-corpus

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache backend/.pytest_cache frontend/dist
