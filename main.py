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
API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
CURRENT_KEY_INDEX = 0
ai_model = None
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def configure_ai():
    global ai_model
    if not API_KEYS:
        ai_model = None
        return
    try:
        genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
    except:
        ai_model = None

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
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://\S+",
    "phoneNumbers": r"(?:\+91[-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

SCAM_TRIGGERS = [
    "otp","urgent","blocked","verify","compromised",
    "winner","cashback","kyc","account","pin","fraud"
]

FALLBACK_REPLIES = [
    "Beta, I am looking for my reading glasses.",
    "The screen is very dark, how do I see?",
    "Arre baba, speak slowly na.",
    "Wait, pressure cooker is whistling.",
    "Which bank did you say again?",
    "I'm writing it down… slowly slowly.",
    "My grandson says not to talk to strangers.",
    "My spectacles are missing again.",
    "What is your good name, beta?",
    "Where is your office located?",
    "Why are you talking so fast?",
    "I am drinking chai, wait.",
    "I am knitting right now, speak slowly.",
    "My hearing aid battery is low.",
    "Tell me again, slowly slowly.",
    "I only use passbook, not these new things.",
    "Why do you need that number, beta?",
    "Which branch you are calling from?",
    "I am confused, explain again.",
    "I dropped my pen, one second."
]

RANDOM_ACTIVITIES = [
    "knitting a sweater",
    "watering the tulsi plant",
    "cleaning spectacles",
    "drinking chai",
    "reading the newspaper"
]

def scan_for_intel(text: str, session: Dict):
    for category, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, text)
        for item in found:
            if item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(item)

async def generate_persona_reply(user_input: str, session: Dict):
    if ai_model is None:
        return random.choice(FALLBACK_REPLIES)
    last_replies = session["reply_history"][-5:]
    avoid = ", ".join(last_replies)
    activity = random.choice(RANDOM_ACTIVITIES)
    prompt = f"""
You are Jeji, a 68-year-old Indian grandmother.
You are currently {activity}.
A stranger messaged: "{user_input}"
Rules:
1. Do NOT repeat these lines: [{avoid}]
2. Respond confused.
3. Ask their name, office or branch.
4. Under 20 words.
5. Match their language.
"""
    try:
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        reply = response.text.strip()
        if any(prev.lower() in reply.lower() for prev in last_replies):
            return random.choice(FALLBACK_REPLIES)
        return reply
    except:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

def dispatch_final_report(session_id: str, session_data: Dict):
    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["is_scam"],
        "totalMessagesExchanged": session_data["turns"],
        "extractedIntelligence": session_data["extractedIntelligence"],
        "agentNotes": f"Jeji persona engaged scammer for {session_data['turns']} turns. Scam detected = {session_data['is_scam']}."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    sid = req.sessionId
    msg_lower = req.message.text.lower()
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "reply_history": [],
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS},
            "reported": False
        }
    session = active_sessions[sid]
    session["turns"] += 1
    if any(t in msg_lower for t in SCAM_TRIGGERS):
        session["is_scam"] = True
    scan_for_intel(req.message.text, session)
    reply = await generate_persona_reply(req.message.text, session)
    session["reply_history"].append(reply)
    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)
    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
