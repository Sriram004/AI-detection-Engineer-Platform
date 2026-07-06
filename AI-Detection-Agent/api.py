from fastapi import FastAPI

from src.analyzer import analyze_alert
from src.database import init_db


app = FastAPI(title="AI Detection Engineer Agent API")
init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(alert: dict):
    return analyze_alert(alert, use_openai=False)
