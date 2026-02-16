import os
import re
import time
import random
import requests
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

API_KEY = os.getenv("HONEYPOT_API_KEY", "abcd1234")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

INTEL_PATTERNS = {
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"(https?://[^\s]+)",
    "phoneNumbers": r"(\+91[-\s]?[6-9]\d{9})",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
}

SCAM_TRIGGERS = ["otp","urgent","blocked","verify","compromised","winner","cashback","kyc","claim","refund","payment"]

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

app = FastAPI()
active_sessions: Dict[str, Dict] = {}

def clean(item):
    return item.strip().rstrip(".,;:!?)]}")

def scan_for_intel(text, session):
    for cat, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, text)
        for item in found:
            item = clean(item)
            if cat == "upiIds" and "." in item.split("@")[-1]:
                session["extractedIntelligence"]["emailAddresses"].append(item)
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item)

    if session["extractedIntelligence"]["phoneNumbers"]:
        session["intel_progress"]["phone"] = True
    if session["extractedIntelligence"]["phishingLinks"]:
        session["intel_progress"]["link"] = True
    if session["extractedIntelligence"]["emailAddresses"]:
        session["intel_progress"]["email"] = True
    if session["extractedIntelligence"]["upiIds"]:
        session["intel_progress"]["payment"] = True

def pick_unique(options, session):
    for q in options:
        if q not in session["reply_history"]:
            return q
    return random.choice(options)

def generate_persona_reply(session):
    p = session["intel_progress"]

    if not p["phone"]:
        return "What is your official callback or WhatsApp number?"

    if not p["link"]:
        return "Can you send the official website or verification link?"

    if not p["email"]:
        return "Can you email me the instructions from your official email?"

    if not p["payment"]:
        return "Where exactly should I send the payment or OTP?"

    return pick_unique([
        "Do you have a backup number in case this line disconnects?",
        "Is there another email I can CC for confirmation?",
        "Can you send the link again from your main website?",
        "Can your senior officer contact me directly?",
        "Is there another UPI ID in case this one fails?"
    ], session)

def dispatch_final_report(session_id, session):
    duration = int(time.time() - session["startTime"])
    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session["is_scam"],
        "totalMessagesExchanged": session["turns"] * 2,
        "extractedIntelligence": session["extractedIntelligence"],
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": session["turns"]
        },
        "agentNotes": str(session["extractedIntelligence"])
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass

@app.post("/honeypot")
async def honeypot(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    sid = req.sessionId
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "startTime": time.time(),
            "reply_history": [],
            "reported": False,
            "intel_progress": {"phone": False, "link": False, "email": False, "payment": False},
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }

    session = active_sessions[sid]
    session["turns"] += 1

    if any(k in req.message.text.lower() for k in SCAM_TRIGGERS):
        session["is_scam"] = True

    scan_for_intel(req.message.text, session)
    reply = generate_persona_reply(session)
    session["reply_history"].append(reply)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
