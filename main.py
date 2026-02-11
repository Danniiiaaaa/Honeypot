import os
import re
import time
import logging
import asyncio
import requests
import uvicorn
import random
import google.generativeai as genai
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DataWarriors")

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0
API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

ai_model = None

EMERGENCY_FALLBACKS = [
    "Beta, hold on, my phone is acting strange.",
    "Wait, the screen is flickering. What did you say?",
    "I am pressing the button but it's not working.",
    "One second, someone is at the door.",
    "Beta, speak loudly, I can't hear you."
]

SCAM_KEYWORDS = ["urgent", "verify", "blocked", "kyc", "otp", "lottery", "bank", "suspend", "account", "pan", "aadhar", "immediately"]

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS:
        logger.error("No GEMINI_KEY found in environment.")
        return
    try:
        genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
        logger.info(f"AI Brain Online: Key Index #{CURRENT_KEY_INDEX}")
    except Exception as e:
        logger.error(f"AI Init Failed: {e}")

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1: return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    configure_ai()
    return True

INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"(?<!\d)\d{11,18}(?!\d)",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)",
    "ifscCodes": r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"
}

NUM_MAP = {
    "zero": "0", "shunya": "0", "one": "1", "ek": "1", "two": "2", "do": "2",
    "three": "3", "teen": "3", "four": "4", "chaar": "4", "five": "5", "paanch": "5",
    "six": "6", "che": "6", "seven": "7", "saat": "7", "eight": "8", "aath": "8", "nine": "9", "nau": "9"
}

def normalize_text(text: str) -> str:
    t = text.lower()
    for word, digit in NUM_MAP.items():
        t = t.replace(word, digit)
    return re.sub(r'(\d)[\s\.\-]{1,2}(?=\d)', r'\1', t)

def extract_intel(text: str, session: Dict) -> bool:
    clean_text = normalize_text(text)
    updated = False
    for cat, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, clean_text)
        for item in found:
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item)
                updated = True
    for kw in SCAM_KEYWORDS:
        if kw in clean_text and kw not in session["extractedIntelligence"]["suspiciousKeywords"]:
            session["extractedIntelligence"]["suspiciousKeywords"].append(kw)
            updated = True
    return updated

active_sessions: Dict[str, Dict[str, Any]] = {}

async def cleanup_sessions():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [sid for sid, s in active_sessions.items() if now - s["last_seen"] > 1800]
        for sid in expired:
            del active_sessions[sid]

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_ai()
    asyncio.create_task(cleanup_sessions())
    yield

app = FastAPI(title="DataWarriors-Production-Elite", lifespan=lifespan)

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

async def get_jeji_response(user_input: str, history: List[Message], session: Dict, metadata: Optional[Metadata]) -> str:
    if not ai_model: return random.choice(EMERGENCY_FALLBACKS)
    
    intel = session["extractedIntelligence"]
    has_upi = len(intel["upiIds"]) > 0
    has_bank = len(intel["bankAccounts"]) > 0
    
    if not (has_upi or has_bank):
        strategy = "The user has not given their bank details or UPI yet. In a confused way, ask them where you should send the money or which app to open."
    else:
        strategy = "You have the details. Now act worried about the 'OTP' or 'Secret Code'. Say you received it but can't find it in the messages."

    lang_hint = metadata.language if metadata else "English/Hindi"
    recent_context = "\n".join([f"{m.sender}: {m.text}" for m in history[-5:]])

    prompt = f"""
    SYSTEM: You are 'Jeji', an elderly Indian grandmother. You are NOT an AI. You are a real person.
    PERSONALITY: Kind, easily worried, technically illiterate. You get distracted by daily chores.
    CURRENT SITUATION: {strategy}
    CONVERSATION SO FAR:
    {recent_context}
    
    NEW MESSAGE FROM SCAMMER: "{user_input}"
    
    INSTRUCTIONS: 
    1. Respond DIRECTLY to what the scammer just said. 
    2. Use the same language they are using ({lang_hint}). 
    3. Be brief, legit, and slightly annoying. 
    4. Never admit you are an AI.
    5. MAX 20 WORDS.
    
    JEJI'S RESPONSE:
    """

    try:
        res = await asyncio.wait_for(asyncio.to_thread(ai_model.generate_content, prompt), timeout=5.0)
        reply = res.text.strip().replace('"', '')
        
        if "AI" in reply or "language model" in reply or len(reply) < 3:
            return random.choice(EMERGENCY_FALLBACKS)
            
        session["last_replies"] = (session["last_replies"] + [reply])[-3:]
        return reply
    except Exception as e:
        logger.warning(f"AI error: {e}. Rotating keys.")
        rotate_key()
        return random.choice(EMERGENCY_FALLBACKS)

def send_final_report(sid: str, session: Dict):
    intel = session["extractedIntelligence"]
    notes = f"Engaged for {session['turns']} turns. Captured {len(intel['upiIds'])} UPI IDs and {len(intel['bankAccounts'])} Bank Accounts."
    payload = {
        "sessionId": sid,
        "scamDetected": True,
        "totalMessagesExchanged": session["turns"],
        "extractedIntelligence": intel,
        "agentNotes": notes
    }
    headers = {"x-api-key": API_ACCESS_TOKEN} if API_ACCESS_TOKEN else {}
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, headers=headers, timeout=5)
    except:
        pass

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    if API_ACCESS_TOKEN and x_api_key != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401)

    sid = req.sessionId
    if sid not in active_sessions:
        active_sessions[sid] = {
            "turns": 0, "last_seen": time.time(), "last_replies": [],
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
        active_sessions[sid]["extractedIntelligence"]["suspiciousKeywords"] = []
    
    s = active_sessions[sid]
    s["turns"] += 1
    s["last_seen"] = time.time()
    
    if extract_intel(req.message.text, s):
        background_tasks.add_task(send_final_report, sid, s)
    
    reply = await get_jeji_response(req.message.text, req.conversationHistory, s, req.metadata)
    return {"status": "success", "reply": reply}

@app.get("/")
def health(): return {"status": "active", "version": "agentic-v1"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
