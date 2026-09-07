from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env into os.environ

import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from Backend.ai_suite import analyze_url_dynamic

app = FastAPI(title="AlphaShield AI Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    html_content: str = ""
    visible_text: str = ""
    has_password_field: bool = False
    has_credit_card_field: bool = False

@app.get("/")
def home():
    return {"status": "AlphaShield Core API Online"}

@app.post("/api/v1/scan-url")
def scan_url_endpoint(req: ScanRequest):
    result = analyze_url_dynamic(
        url=req.url, 
        html_content=req.html_content,
        has_password_field=req.has_password_field,
        has_credit_card_field=req.has_credit_card_field
    )
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)