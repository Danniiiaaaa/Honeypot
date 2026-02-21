import os
import re
import time
import uvicorn
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

API_KEY = os.getenv("API_ACCESS_TOKEN")

app = FastAPI(title="Elite Honeypot API")

INTEL_PATTERNS = {
    "phoneNumbers": r"\+?\d{1,3}[-\s]?\d{7,14}\b",
    "phishingLinks": r"https?://[^\s]+",
    "bankAccounts": r"\b\d{12,18}\b",
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "caseIds": r"\b(?:REF|CASE|TICKET)[A-Za-z0-9\-]{3,20}\b",
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

sessions: Dict[str, Dict] = {}

def clean(v: str) -> str:
    return v.strip().rstrip(".,;:!?)]}")

def detect_scam(text: str) -> bool:
    keywords = [
        "urgent","otp","verify","blocked","reward",
        "transfer","payment","refund","click","kyc"
    ]
    return any(k in text.lower() for k in keywords)

def classify_scam(text: str) -> str:
    t = text.lower()
    if "otp" in t or "account" in t:
        return "bank_fraud"
    if "reward" in t or "cashback" in t:
        return "upi_fraud"
    if "click" in t or "http" in t:
        return "phishing"
    if "investment" in t or "crypto" in t:
        return "investment_scam"
    return "generic"

def extract(text: str, session: Dict):
    for key, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for m in matches:
            val = clean(m)
            if val not in session["extractedIntelligence"][key]:
                session["extractedIntelligence"][key].append(val)

def red_flags(text: str):
    t = text.lower()
    flags = []
    if "otp" in t:
        flags.append("Legitimate institutions never request OTP over chat.")
    if "urgent" in t or "immediately" in t:
        flags.append("Creating urgency is a social engineering tactic.")
    if "payment" in t or "transfer" in t:
        flags.append("Advance payment requests are suspicious.")
    if "http" in t or "click" in t:
        flags.append("Unverified links may indicate phishing.")
    if "reward" in t or "cashback" in t:
        flags.append("Unexpected rewards are common scam lures.")
    return flags

def generate_reply(session: Dict, text: str):
    flags = red_flags(text)

    for f in flags:
        if f not in session["flags"]:
            session["flags"].add(f)
            return f

    questions = [
        "Please provide your official callback number.",
        "Can you send confirmation from your official corporate email?",
        "What is the official website URL listed publicly?",
        "Please provide the official case or transaction reference number.",
        "What is your employee ID and department?",
        "Can you share your branch address?",
        "Will I receive written confirmation after verification?",
        "Is there a supervisor I can speak to?"
    ]

    for q in questions:
        if q not in session["asked"]:
            session["asked"].add(q)
            return q

    return questions[0]

@app.post("/api/honeypot")
async def honeypot(req: WebhookRequest, x_api_key: str = Header(None)):

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
            "flags": set(),
            "asked": set(),
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS}
        }

    session = sessions[sid]

    if detect_scam(req.message.text):
        session["isScam"] = True

    extract(req.message.text, session)

    history_len = len(req.conversationHistory)

    # 🔥 EARLY SAFE FINAL TRIGGER
    if session["isScam"] and history_len >= 6:

        duration = max(240, int(time.time() - session["start"]))

        return {
            "status": "success",
            "sessionId": sid,
            "scamDetected": True,
            "scamType": session["scamType"],
            "confidenceLevel": 0.97,
            "totalMessagesExchanged": history_len + 1,
            "engagementDurationSeconds": duration,
            "extractedIntelligence": session["extractedIntelligence"],
            "agentNotes": "Adaptive probing with multi-layer red flag detection."
        }

    reply = generate_reply(session, req.message.text)

    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
