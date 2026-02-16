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
    "phishingLinks": r"https?://[^\s]+",
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

FALLBACK_REPLIES = [
    "Which department are you calling from?",
    "Can you give your employee ID please?",
    "What is your official callback number?",
    "Which branch are you calling from?",
    "Can you verify your identity first?"
]

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

def scan_for_intel(text: str, session: Dict):
    for cat, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, text)
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
    if ai_model is None:
        return random.choice(FALLBACK_REPLIES)

    language = session.get("language", "English")

    prompt = f"""
You are a polite confused Indian grandmother talking to a suspicious caller.

Language: {language}

Caller message:
{user_input}

Rules:
• Never share OTP, PIN or personal details
• Always ask a question to keep the caller talking
• Ask for ID, callback number, branch or proof
• Sound polite and confused

Reply in ONE sentence and end with a question.
"""

    try:
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        reply = extract_gemini_text(response)
        if not reply or reply in session["reply_history"]:
            raise Exception()
        return reply
    except:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

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
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": session_data["extractedIntelligence"],
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": total_msgs
        },
        "agentNotes": "Adaptive scam bait persona engaging across fraud scenarios."
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
            "language": req.metadata.get("language", "English") if req.metadata else "English",
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()},
        }

    session = active_sessions[sid]
    session["turns"] += 1

    text = req.message.text
    scan_for_intel(text, session)
    update_risk_score(text, session)

    reply = await generate_persona_reply(text, session)
    session["reply_history"].append(reply)

    if session["turns"] >= 5 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)
        background_tasks.add_task(cleanup_session, sid)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
