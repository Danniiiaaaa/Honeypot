import os
import re
import time
import asyncio
import requests
import uvicorn
import random
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager
from fastapi import Request

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

ai_model = None

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS: return
    try:
        genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
    except Exception:
        rotate_key()

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1: return False
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

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

SCAM_TRIGGERS = ["otp", "urgent", "blocked", "verify", "compromised", "winner", "cashback", "kyc", "claim"]

FALLBACK_REPLIES = [
    "Beta, my reading glasses are missing. Can you read that again?",
    "Wait, I am pressing the button but it's not working. Is it the green one?",
    "Beta, phone ki screen bohot dark hai, kuch dikh nahi raha.",
    "Which bank did you say? SBI or HDFC? I have accounts in both.",
    "Beta, hold on, the pressure cooker is whistling!",
    "I am writing it down with my pen, please go slow."
]

def scan_for_intel(text: str, session: Dict):
    accounts = re.findall(INTEL_PATTERNS["bankAccounts"], text)
    for acc in accounts:
        if acc not in session["extractedIntelligence"]["bankAccounts"]:
            session["extractedIntelligence"]["bankAccounts"].append(acc.strip())

    phones = re.findall(INTEL_PATTERNS["phoneNumbers"], text)
    for phone in phones:
        if not any(phone in acc for acc in session["extractedIntelligence"]["bankAccounts"]):
            if phone not in session["extractedIntelligence"]["phoneNumbers"]:
                session["extractedIntelligence"]["phoneNumbers"].append(phone.strip())

    for cat in ["upiIds", "phishingLinks", "emailAddresses"]:
        found = re.findall(INTEL_PATTERNS[cat], text)
        for item in found:
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item.strip())

async def generate_persona_reply(user_input: str, session: Dict) -> str:
    if ai_model is None: return random.choice(FALLBACK_REPLIES)
    
    text = user_input.lower()
    recent_history = ", ".join(session["reply_history"][-2:])
    
    if any(x in text for x in ["otp", "one time"]):
        instruction = "Act concerned but refuse to share OTP. Ask which department they are from and their name."
    elif any(x in text for x in ["sbi", "bank", "fraud", "blocked", "freeze"]):
        instruction = "Tell them you are worried. Ask for their official employee ID and branch location."
    elif any(x in text for x in ["urgent", "immediately", "fast", "act now"]):
        instruction = "Say you need to record this for your son. Ask for their official callback number."
    elif any(x in text for x in ["account", "number", "details"]):
        instruction = "Refuse to share details. Ask for their staff authorization code first."
    elif any(x in text for x in ["payment", "upi", "txn", "refund"]):
        instruction = "Say you want to verify them. Ask for their employee badge number and UPI ID."
    else:
        instruction = "Act like a slow, polite grandmother. Ask for their authorized banking officer identification code."

    prompt = f"""
    Role: Jeji, a 68-year-old grandmother. 
    Tone: Polite, slow, easily worried. 
    Situation: {random.choice(['Looking for glasses', 'Drinking tea', 'Cooking dal'])}.
    Scammer said: "{user_input}"
    Instruction: {instruction}
    Directives:
    - Reply in the same language as the scammer (English, Hindi, or Hinglish).
    - DO NOT repeat these previous lines: [{recent_history}].
    - Use natural, grandmotherly phrasing. Max 25 words. Stay in character.
    """

    try:
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        reply = response.text.strip()
        if not reply or any(prev.lower() in reply.lower() for prev in session["reply_history"]):
            available = [r for r in FALLBACK_REPLIES if r not in session["reply_history"]]
            return random.choice(available) if available else FALLBACK_REPLIES[0]
        return reply
    except Exception:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

def dispatch_final_report(session_id: str, session_data: Dict):
    duration = int(time.time() - session_data["startTime"])
    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["is_scam"],
        "totalMessagesExchanged": session_data["turns"] * 2,
        "extractedIntelligence": session_data["extractedIntelligence"],
        "agentNotes": f"Persona Jeji maintained engagement for {duration}s. Strategy: Confused grandmother requesting identity verification."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception:
        pass

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    sid = req.sessionId
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False, "turns": 0, "startTime": time.time(),
            "reply_history": [], "reported": False,
            "extractedIntelligence": {
                "phoneNumbers": [], "bankAccounts": [], "upiIds": [], "phishingLinks": [], "emailAddresses": []
            }
        }
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    if any(kw in req.message.text.lower() for kw in SCAM_TRIGGERS):
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
