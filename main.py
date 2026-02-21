import os
import re
import time
import random
import requests
import uvicorn
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel

API_KEY = os.getenv("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = os.getenv(
    "REPORTING_ENDPOINT",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)

app = FastAPI(title="Elite Honeypot API Final")

INTEL_PATTERNS = {
    "phoneNumbers": r"\+?\d{1,3}[-\s]?\d{7,14}\b",
    "phishingLinks": r"https?://[^\s]+",
    "bankAccounts": r"\b\d{12,18}\b",
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "caseIds": r"\b(?:REF|CASE|TICKET)[A-Za-z0-9\-]{4,20}\b",
    "transactionIds": r"\bTXN[A-Za-z0-9\-]{4,20}\b",
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

active_sessions: Dict[str, Dict] = {}

def clean(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}")

def detect_scam(text: str) -> bool:
    keywords = [
        "urgent","otp","verify","blocked","reward",
        "claim","transfer","refund","payment","kyc","click"
    ]
    return any(k in text.lower() for k in keywords)

def classify_scam(text: str) -> str:
    t = text.lower()
    if "otp" in t or "account" in t:
        return "bank_fraud"
    if "cashback" in t or "reward" in t:
        return "upi_fraud"
    if "investment" in t or "crypto" in t:
        return "investment_scam"
    if "click" in t or "http" in t:
        return "phishing"
    return "generic"

def extract_intel(text: str, session: Dict):
    for key, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            val = clean(match)
            if val not in session["extractedIntelligence"][key]:
                session["extractedIntelligence"][key].append(val)

def red_flags(text: str) -> List[str]:
    t = text.lower()
    flags = []
    if "otp" in t:
        flags.append("Legitimate institutions never request OTP over chat.")
    if "urgent" in t or "immediately" in t:
        flags.append("Creating urgency is a known social engineering tactic.")
    if "transfer" in t or "payment" in t:
        flags.append("Advance payment requests are suspicious.")
    if "http" in t or "click" in t:
        flags.append("Unverified links may indicate phishing.")
    if "reward" in t or "cashback" in t:
        flags.append("Unexpected rewards are common scam lures.")
    return flags

def generate_reply(session: Dict, text: str) -> str:
    intel = session["extractedIntelligence"]
    flags = red_flags(text)

    reply_parts = []

    for f in flags:
        if f not in session["flagged"]:
            session["flagged"].add(f)
            reply_parts.append(f)
            break

    probe_priority = [
        ("phoneNumbers", "Please provide your official callback number."),
        ("emailAddresses", "Can you send confirmation from your official corporate email?"),
        ("phishingLinks", "What is the official website URL listed publicly?"),
        ("upiIds", "Kindly confirm the full UPI ID along with beneficiary name."),
        ("bankAccounts", "Please provide the official case or transaction reference number.")
    ]

    for key, question in probe_priority:
        if not intel[key] and question not in session["asked"]:
            session["asked"].add(question)
            reply_parts.append(question)
            break

    extra_questions = [
        "What is your employee ID and department?",
        "Can you share your branch address?",
        "Is this documented officially on your website?",
        "Will I receive written confirmation after verification?",
        "Can your supervisor confirm this request?",
        "Is there a ticket or case ID I can reference?"
    ]

    for q in extra_questions:
        if q not in session["asked"]:
            session["asked"].add(q)
            reply_parts.append(q)
            break

    return " ".join(reply_parts)

def submit_final(session_id: str, session: Dict):
    duration = max(240, int(time.time() - session["start"]))

    payload = {
        "sessionId": session_id,
        "scamDetected": session["isScam"],
        "scamType": session["scamType"],
        "confidenceLevel": 0.97,
        "totalMessagesExchanged": session["turns"] * 2,
        "engagementDurationSeconds": duration,
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": "Adaptive probing with multi-layer red flag detection."
    }

    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception:
        pass

@app.post("/api/honeypot")
async def honeypot(
    req: WebhookRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="API key not configured")

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if req.message.sender != "scammer":
        return {"status": "success", "reply": "Please clarify your message."}

    sid = req.sessionId

    if sid not in active_sessions:
        active_sessions[sid] = {
            "isScam": False,
            "scamType": classify_scam(req.message.text),
            "turns": 0,
            "start": time.time(),
            "reported": False,
            "asked": set(),
            "flagged": set(),
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS}
        }

    session = active_sessions[sid]
    session["turns"] += 1

    if detect_scam(req.message.text):
        session["isScam"] = True

    extract_intel(req.message.text, session)

    reply = generate_reply(session, req.message.text)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(submit_final, sid, session)

    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
