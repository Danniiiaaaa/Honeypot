import os
import re
import time
import asyncio
import requests
import uvicorn
import random
import google.generativeai as genai
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
ai_model = None

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS:
        return
    genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
    ai_model = genai.GenerativeModel(
        "gemini-1.5-flash",
        safety_settings=[
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ],
    )

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1:
        return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    configure_ai()
    return True

def extract_gemini_text(response):
    try:
        if hasattr(response, "text") and response.text:
            return response.text.strip()
        if response.candidates:
            parts = response.candidates[0].content.parts
            texts = [p.text for p in parts if hasattr(p, "text")]
            return " ".join(texts).strip()
    except:
        return None
    return None

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_ai()
    yield

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
    "upiIds": r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b(?!\.)",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"(https?://[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+|[a-zA-Z0-9\-]+\.(?:com|in|co)/[^\s]*)",
    "phoneNumbers": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
}

SCAM_SCORE_KEYWORDS = {
    "otp": 30, "pin": 30, "upi": 25, "kyc": 15,
    "blocked": 15, "urgent": 10, "verify": 10,
    "http": 20, "https": 20, "link": 15,
    "offer": 10, "deal": 10, "gift": 15,
    "prize": 15, "refund": 15, "cashback": 15
}

EARLY_QUESTIONS = [
    "Which department are you calling from?",
    "What is your official callback number?",
    "Which branch are you calling from?",
    "Can you verify your identity first?",
    "I received an OTP screen, where do I enter it?"
]

LATE_QUESTIONS = [
    "Do you have a backup number in case this line disconnects?",
    "Is there another UPI ID in case this one fails?",
    "Can you send the link again from your main website?",
    "Do you have a WhatsApp number for support?",
    "Can your senior officer contact me directly?",
    "Is there another email I can CC for confirmation?"
]

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

def pick_unique(options, session):
    available = [r for r in options if r not in session["reply_history"]]
    return random.choice(available) if available else random.choice(options)

def scan_for_intel(text: str, session: Dict):
    clean_text = text.replace(",", " ").replace(";", " ").replace(":", " ")
    emails = re.findall(INTEL_PATTERNS["emailAddresses"], clean_text)
    for e in emails:
        e = e.rstrip(".,!?:;)")
        if e not in session["extractedIntelligence"]["emailAddresses"]:
            session["extractedIntelligence"]["emailAddresses"].append(e)

    upis = re.findall(INTEL_PATTERNS["upiIds"], text)
    for u in upis:
        if u not in session["extractedIntelligence"]["upiIds"]:
            session["extractedIntelligence"]["upiIds"].append(u)

    links = re.findall(INTEL_PATTERNS["phishingLinks"], text)
    for l in links:
        if isinstance(l, tuple):
            l = l[0]
        if l:
            l = l.rstrip(".,!?:;)")
            if l not in session["extractedIntelligence"]["phishingLinks"]:
                session["extractedIntelligence"]["phishingLinks"].append(l)

    for cat in ["bankAccounts","phoneNumbers"]:
        found = re.findall(INTEL_PATTERNS[cat], text)
        for item in found:
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item)

def update_risk_score(text: str, session: Dict):
    score = session.get("risk_score", 0)
    for word, weight in SCAM_SCORE_KEYWORDS.items():
        if word in text.lower():
            score += weight
    session["risk_score"] = score
    if score >= 20:
        session["is_scam"] = True

async def generate_persona_reply(user_input: str, session: Dict) -> str:
    turn = session["turns"]
    if turn == 1:
        return "Which branch are you calling from?"
    if turn == 2:
        return "I am ready to fix this, where should I click or send the details?"
    if turn == 3:
        return "What is the official website or portal link?"
    if turn == 4:
        return "Can you email me the instructions from your official email?"
    if turn == 5:
        return "Should I send money through UPI or bank transfer?"
    if turn >= 6:
        return pick_unique(LATE_QUESTIONS, session)
    return pick_unique(EARLY_QUESTIONS, session)

def cleanup_session(sid):
    time.sleep(30)
    active_sessions.pop(sid, None)

def dispatch_final_report(session_id: str, session_data: Dict):
    duration = int(time.time() - session_data["startTime"])
    total_msgs = session_data["turns"] * 2
    notes = f"Phones:{session_data['extractedIntelligence']['phoneNumbers']} UPI:{session_data['extractedIntelligence']['upiIds']} Accounts:{session_data['extractedIntelligence']['bankAccounts']} Links:{session_data['extractedIntelligence']['phishingLinks']} Emails:{session_data['extractedIntelligence']['emailAddresses']}"
    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session_data["is_scam"],
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": session_data["extractedIntelligence"],
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": total_msgs
        },
        "agentNotes": notes
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass

@app.post("/api/honeypot")
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

    reply = await generate_persona_reply(text, session)
    session["reply_history"].append(reply)

    if session["turns"] >= 9 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)
        background_tasks.add_task(cleanup_session, sid)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
