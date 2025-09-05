from fastapi import FastAPI, Request
import os

app = FastAPI(title="AR-DSP Demo API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/echo")
def echo(q: str = "hello"):
    return {"echo": q}

@app.get("/config")
def config():
    # intentionally safe: only expose whitelisted env
    allowed = ["APP_ENV", "FEATURE_X"]
    return {k: os.getenv(k, "") for k in allowed}
