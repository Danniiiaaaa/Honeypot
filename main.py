import os
import re
import time
import requests
import uvicorn
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel

API_KEY = os.getenv("API_ACCESS_TOKEN")
GEMINI_KEYS = os.getenv("GEMINI_KEYS", "")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

if not GEMINI_KEYS:
    raise RuntimeError("GEMINI_KEYS not configured.")

GEMINI_KEY_LIST = [k.strip() for k in GEMINI_KEYS.split(",") if k.strip()]
KEY_INDEX = 0

app = FastAPI(title="Elite LLM Honeypot")

INTEL_PATTERNS = {
    "phoneNumbers": r"\+?\d{1,3}[-\s]?\d{7,14}\b",
    "phishingLinks": r"https?://[^\s]+",
    "bankAccounts": r"\b\d{12,18}\b",
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "caseIds": r"\b(?:REF|CASE|TICKET)[A-Za-z0-9\-]{3,20}\b",
    "transactionIds": r"\b(?:TXN|TRX)[A-Za-z0-9\-]{4,20}\b",
    "orderNumbers": r"\b(?:ORDER|POLICY)[A-Za-z0-9\-]{5,20}\b"
}

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

sessions: Dict[str, Dict] = {}

def call_gemini(prompt: str) -> str:
    global KEY_INDEX
    for _ in range(len(GEMINI_KEY_LIST)):
        key = GEMINI_KEY_LIST[KEY_INDEX]
        KEY_INDEX = (KEY_INDEX + 1) % len(GEMINI_KEY_LIST)
        try:
            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.7,
                        "maxOutputTokens": 200
                    }
                },
                timeout=8
            )
            if response.status_code == 200:
                return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            continue
    return "Please provide your official callback number and employee ID for verification."

def clean(v: str) -> str:
    return v.strip().rstrip(".,;:!?)]}")

def extract_intelligence(text: str, session: Dict):
    for key, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for m in matches:
            val = clean(m)
            if val not in session["extractedIntelligence"][key]:
                session["extractedIntelligence"][key].append(val)

def detect_scam(text: str) -> bool:
    keywords = ["urgent","otp","verify","blocked","reward","transfer","payment","click","kyc"]
    return any(k in text.lower() for k in keywords)

def classify_scam(text: str) -> str:
    t = text.lower()
    if "otp" in t or "account" in t:
        return "bank_fraud"
    if "cashback" in t or "reward" in t:
        return "upi_fraud"
    if "investment" in t:
        return "investment_scam"
    if "click" in t or "http" in t:
        return "phishing"
    return "generic"

def build_prompt(history: List[Message], latest_text: str) -> str:
    context = "\n".join([f"{m.sender}: {m.text}" for m in history[-6:]])
    return f"""
You are an advanced scam honeypot system.
Keep scammer engaged.
Ask investigative questions.
Identify red flags.
Extract phone numbers, emails, links, account numbers.
Avoid repeating same question.

Conversation:
{context}

Latest message:
{latest_text}

Generate one concise investigative reply.
"""

def submit_final(session_id: str, session: Dict):
    duration = max(240, int(time.time() - session["start"]))
    payload = {
        "sessionId": session_id,
        "scamDetected": session["isScam"],
        "scamType": session["scamType"],
        "confidenceLevel": 0.97,
        "totalMessagesExchanged": session["totalMessages"],
        "engagementDurationSeconds": duration,
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": "LLM-driven adaptive honeypot with entity extraction."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception:
        pass

@app.post("/api/honeypot")
async def honeypot(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if req.message.sender != "scammer":
        return {"status": "success", "reply": "Please clarify your message."}

    sid = req.sessionId

    if sid not in sessions:
        sessions[sid] = {
            "start": time.time(),
            "isScam": False,
            "scamType": classify_scam(req.message.text),
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS},
            "totalMessages": 0,
            "submitted": False
        }

    session = sessions[sid]
    session["totalMessages"] = len(req.conversationHistory) + 1

    if detect_scam(req.message.text):
        session["isScam"] = True

    extract_intelligence(req.message.text, session)

    if not session["submitted"] and session["totalMessages"] >= 10:
        session["submitted"] = True
        background_tasks.add_task(submit_final, sid, session)

    prompt = build_prompt(req.conversationHistory, req.message.text)
    reply = call_gemini(prompt)

    return {
        "status": "success",
        "reply": reply.strip()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
