.PHONY: install dev-install lint format typecheck security test check train replay serve compose-up compose-down

install:
	pip install -e .

dev-install:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy src

security:
	bandit -c pyproject.toml -r src
	pip-audit --progress-spinner=off

test:
	pytest

# Everything CI runs, in one shot, before you push.
check: lint typecheck security test

train:
	nids train --dataset synthetic --out models/anomaly_model.joblib

replay:
	nids replay tests/fixtures/demo_traffic.pcap

serve:
	nids serve --reload

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
