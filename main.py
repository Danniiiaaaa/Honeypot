import os
import re
import asyncio
import requests
import uvicorn
import random
import google.generativeai as genai
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0

API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

ai_model = None

FALLBACK_POOL = [
    "Beta, signal is low.",
    "Looking for my glasses.",
    "Pressure cooker is whistling.",
    "Screen went dark.",
    "One minute beta.",
    "Grandson is calling.",
    "Finding my pen."
]

SCAM_KEYWORDS = ["urgent", "verify", "blocked", "kyc", "otp", "lottery", "bank", "suspend", "account"]

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS: return
    try:
        genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
    except: pass

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1: return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    configure_ai()
    return True

INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{9,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}",
    "ifscCodes": r"[A-Z]{4}0[A-Z0-9]{6}"
}

NUM_MAP = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9", "ek": "1", "do": "2"}

def normalize_scam_text(text: str) -> str:
    t = text.lower()
    for word, digit in NUM_MAP.items(): t = t.replace(word, digit)
    return re.sub(r'(\d)[\s\.\-]{1,2}(?=\d)', r'\1', t)

def extract_intel(text: str, session: Dict) -> bool:
    clean_text = normalize_scam_text(text)
    new_data = False
    for category, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, clean_text)
        for item in found:
            if item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(item)
                new_data = True
    for kw in SCAM_KEYWORDS:
        if kw in clean_text and kw not in session["extractedIntelligence"]["suspiciousKeywords"]:
            session["extractedIntelligence"]["suspiciousKeywords"].append(kw)
            new_data = True
    return new_data

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_ai()
    yield

app = FastAPI(title="DataWarriors-Speed-Edition", lifespan=lifespan)

class Message(BaseModel):
    sender: str
    text: str

class Metadata(BaseModel):
    language: Optional[str] = "English"

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

active_sessions: Dict[str, Dict[str, Any]] = {}

async def get_jeji_response(user_input: str, history: List[Message], session: Dict, metadata: Optional[Metadata]) -> str:
    if not ai_model: return random.choice(FALLBACK_POOL)
    
    last_replies = session.get("last_replies", [])
    has_intel = len(session["extractedIntelligence"]["upiIds"]) > 0
    bait = "Ask for ID/UPI details." if not has_intel else "Keep them talking about bank branch."
    lang = metadata.language if metadata else "English"
    
    context_msgs = history[-2:] if history else []
    context_str = "\n".join([f"{m.sender}: {m.text}" for m in context_msgs])

    prompt = f"""
    Role: Indian Grandma 'Jeji'. 
    Identity: Concerned, worried about bank/pension, technically illiterate.
    Language: {lang}. 
    Goal: {bait}
    Previous Context: {context_str}
    Input: {user_input}
    Directive: Be legit, responsive, and brief. No AI mentions. MAX 20 WORDS.
    Response:
    """

    try:
        res = await asyncio.wait_for(asyncio.to_thread(ai_model.generate_content, prompt), timeout=3.5)
        reply = res.text.strip()
        session["last_replies"] = (last_replies + [reply])[-2:]
        return reply
    except:
        rotate_key()
        return random.choice(FALLBACK_POOL)

def send_final_report(sid: str, session: Dict):
    payload = {
        "sessionId": sid,
        "scamDetected": True,
        "totalMessagesExchanged": session["turns"],
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": "DataWarriors Responsive Agent reporting intel."
    }
    headers = {"x-api-key": API_ACCESS_TOKEN} if API_ACCESS_TOKEN else {}
    try: requests.post(REPORTING_ENDPOINT, json=payload, headers=headers, timeout=2)
    except: pass

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    if API_ACCESS_TOKEN and x_api_key != API_ACCESS_TOKEN: raise HTTPException(status_code=401)
    
    sid = req.sessionId
    if sid not in active_sessions:
        active_sessions[sid] = {"turns": 0, "last_replies": [], "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}}
        active_sessions[sid]["extractedIntelligence"]["suspiciousKeywords"] = []
    
    s = active_sessions[sid]
    s["turns"] += 1
    
    if extract_intel(req.message.text, s):
        background_tasks.add_task(send_final_report, sid, s)
    
    reply = await get_jeji_response(req.message.text, req.conversationHistory, s, req.metadata)
    return {"status": "success", "reply": reply}

@app.get("/")
def health(): return {"status": "active"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
