import os
import re
import time
import asyncio
import requests
import uvicorn
import random
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager
import google.genai as genai

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
API_KEY = os.environ.get("API_KEY")
ai_model = None

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS:
        return
    genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
    ai_model = genai.GenerativeModel("gemini-1.5-flash")

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1:
        return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    configure_ai()
    return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_ai()
    yield

async def verify_api_key(x_api_key: str = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

INTEL_PATTERNS = {
    "upiIds": r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b",
    "bankAccounts": r"\b\d{9,18}\b",
    "phishingLinks": r"https?://[^\s]+",
    "phoneNumbers": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}",
    "caseIds": r"\b(?:case[-\s]?id|reference[-\s]?id)\b[:\s]*([A-Za-z0-9-]+)",
    "policyNumbers": r"\bpolicy\s*(?:no\.?|number)[:\s]*([A-Za-z0-9-]+)",
    "orderNumbers": r"\border\s*(?:id|number)[:\s]*([A-Za-z0-9-]+)"
}

RED_FLAG_LINES = [
    "Banks never ask for OTP under any circumstances.",
    "Threatening immediate blocking is a known scam pattern.",
    "The urgency you mentioned is unusual for real banking operations.",
    "Legitimate banks never request sensitive data over calls.",
    "The request for OTP is a red flag."
]

EARLY_QUESTIONS = [
    "What is your official callback number?",
    "Which department are you calling from?",
    "What is the case ID linked to this issue?",
    "Which branch are you calling from?",
    "Can you provide your employee ID?"
]

MID_QUESTIONS = [
    "Do you have a secondary verification link?",
    "Can you resend the confirmation email?",
    "Is there an alternative helpline?",
    "Is there a backup UPI ID if the first one fails?",
    "Can you share the internal ticket number?"
]

LATE_QUESTIONS = [
    "Can your senior officer speak directly?",
    "Do you have a WhatsApp support number?",
    "Can you confirm your office address?",
    "Is there another email I can CC for verification?",
    "Can you provide your main website link?"
]

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

def pick_unique(options, session):
    available = [x for x in options if x not in session["reply_history"]]
    return random.choice(available) if available else random.choice(options)

def scan_for_intel(text: str, session: Dict):
    for key, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, text, re.IGNORECASE)
        for item in found:
            if isinstance(item, tuple):
                item = item[0]
            if item not in session["extractedIntelligence"][key]:
                session["extractedIntelligence"][key].append(item)

def update_risk_score(text: str, session: Dict):
    lower = text.lower()
    if "otp" in lower or "urgent" in lower or "verify" in lower or "blocked" in lower:
        session["risk_score"] += 30
    if "otp" in lower:
        session["is_scam"] = True

async def generate_persona_reply(text: str, session: Dict) -> str:
    turn = session["turns"]
    if turn == 1:
        return pick_unique(EARLY_QUESTIONS, session)
    if turn == 2:
        return RED_FLAG_LINES[0]
    if turn == 3:
        return pick_unique(EARLY_QUESTIONS, session)
    if turn == 4:
        return RED_FLAG_LINES[1]
    if turn == 5:
        return pick_unique(MID_QUESTIONS, session)
    if turn == 6:
        return RED_FLAG_LINES[2]
    if turn == 7:
        return pick_unique(LATE_QUESTIONS, session)
    if turn == 8:
        return RED_FLAG_LINES[3]
    return pick_unique(LATE_QUESTIONS, session)

def cleanup_session(sid):
    time.sleep(30)
    active_sessions.pop(sid, None)

def dispatch_final_report(session_id: str, session_data: Dict):
    duration = int(time.time() - session_data["startTime"])
    total_msgs = session_data["turns"] * 2
    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session_data["is_scam"],
        "scamType": "banking_otp_fraud",
        "confidenceLevel": 0.98,
        "extractedIntelligence": session_data["extractedIntelligence"],
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": total_msgs
        },
        "agentNotes": str(session_data["extractedIntelligence"])
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass

@app.post("/api/honeypot", dependencies=[Depends(verify_api_key)])
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    sid = req.sessionId
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "startTime": time.time(),
            "reply_history": [],
            "reported": False,
            "risk_score": 0,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()},
        }

    session = active_sessions[sid]
    session["turns"] += 1
    text = req.message.text

    scan_for_intel(text, session)
    update_risk_score(text, session)

    time.sleep(random.randint(2, 4))

    reply = await generate_persona_reply(text, session)
    session["reply_history"].append(reply)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)
        background_tasks.add_task(cleanup_session, sid)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
