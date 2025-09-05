import argparse, os, re, subprocess, json, sys, pathlib, hashlib

CRITICAL_PATHS = [
    ("app/payments", 30),
    ("app/", 20),
    ("k8s/", 10),
    ("policy/", 5),
    ("docs/", 1),
]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN( RSA)? PRIVATE KEY-----"),
    re.compile(r"(?i)api_key\s*=\s*['\"][A-Za-z0-9_\-]{16,}"),
]

def git_changed_files(base_branch):
    try:
        # fetch base if missing (best-effort)
        subprocess.run(["git", "fetch", "origin", base_branch, "--depth", "1"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"], capture_output=True, text=True, check=True)
        return [p.strip() for p in r.stdout.splitlines() if p.strip()]
    except Exception:
        # fallback: all tracked files
        r = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
        return [p.strip() for p in r.stdout.splitlines() if p.strip()]

def path_weight(path):
    score = 0
    for prefix, weight in CRITICAL_PATHS:
        if path.startswith(prefix):
            score = max(score, weight)
    if path.endswith(("requirements.txt", "pyproject.toml", "package.json", "pom.xml")):
        score += 15  # dependency changes are riskier
    return score

def detect_secrets(paths):
    secret_hits = 0
    for p in paths:
        try:
            with open(p, "r", errors="ignore") as f:
                data = f.read()
                for pat in SECRET_PATTERNS:
                    if pat.search(data):
                        secret_hits += 1
                        break
        except Exception:
            pass
    return min(secret_hits * 20, 40)

def prior_vuln_density_cache():
    # simplistic: hash repo root files to pseudo-random but stable density in [0,20]
    files = sorted([p for p in pathlib.Path(".").glob("**/*") if p.is_file() and ".git" not in str(p)])
    h = hashlib.sha256()
    for p in files[:200]:
        try:
            h.update(p.name.encode())
        except Exception:
            pass
    return int(h.hexdigest(), 16) % 21  # 0..20

def threat_env_weight():
    level = os.getenv("THREAT_LEVEL", "low").lower()
    return {"low": 0, "elevated": 10, "severe": 25}.get(level, 0)

def band(score):
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-branch", default="main")
    args = ap.parse_args()

    changed = git_changed_files(args.base_branch)
    base = sum(path_weight(p) for p in changed)
    secrets = detect_secrets(changed)
    prior = prior_vuln_density_cache()
    threat = threat_env_weight()

    # Normalize
    raw = base + secrets + prior + threat
    # rough normalization to [0,100]
    score = max(0, min(100, int(raw / 3)))
    risk_band = band(score)

    result = {"score": score, "band": risk_band, "changed_files": changed}
    print(json.dumps(result, indent=2))

    # exit code 0 always; CI consumes JSON
    return 0

if __name__ == "__main__":
    sys.exit(main())
