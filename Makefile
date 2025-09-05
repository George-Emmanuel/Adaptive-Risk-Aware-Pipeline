.PHONY: setup risk sast sca build scan policy run

setup:
	python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

risk:
	python scripts/risk_score.py --base-branch main

sast:
	bandit -q -r app

sca:
	pip-audit || true

build:
	docker build -t ardsp:local .

scan:
	trivy image --exit-code 0 --severity HIGH,CRITICAL ardsp:local

policy:
	conftest test k8s

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000
