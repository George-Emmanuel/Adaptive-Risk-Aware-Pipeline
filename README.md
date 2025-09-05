# Adaptive Risk-Aware DevSecOps Pipeline (AR-DSP) — Prototype

This is a minimal working prototype that demonstrates:
- Dynamic risk scoring per commit.
- Adaptive CI steps (SAST, SCA, container scan, policy-as-code) driven by risk.
- Policy enforcement with OPA (via conftest).
- Optional DAST baseline on high-risk changes.

## Quick Start (Local)
```bash
# 1) Create venv and install tools
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 2) Run risk scoring locally (simulates a CI run)
python scripts/risk_score.py --base-branch main

# 3) Run static analysis locally
bandit -q -r app || true
pip-audit || true

# 4) Build & scan container (requires Docker and Trivy)
docker build -t ardsp-app:local .
trivy image --exit-code 0 --severity HIGH,CRITICAL ardsp-app:local

# 5) Policy checks (requires conftest)
conftest test k8s

# 6) (Optional) Run app
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## GitHub Actions
The workflow `.github/workflows/ardsp.yml` shows a complete pipeline:
- Computes risk score.
- Conditionally runs enhanced checks for MEDIUM/HIGH risk.
- Publishes SARIF for GitHub code scanning (Bandit, pip-audit) by default.

## Risk Model (simplified for prototype)
- File path criticality (e.g., `app/payments/*` > `docs/*`).
- Secrets heuristics.
- Dependency changes.
- Threat level input via env (`THREAT_LEVEL=low|elevated|severe`).
- Prior vuln density approximation (cached score file).

Outputs a score [0,100] and band LOW | MEDIUM | HIGH via GitHub Actions outputs.

## Notes
- Tools are pinned to reasonable versions in `requirements.txt`.
- Replace `app/` with your services and extend `policy/` for your controls.
- For a real bank pipeline, integrate enterprise tools (Checkmarx, Snyk, X-Force, MISP).

