import os
import re
import time
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
    "Beta, please wait... signal is very low.",
    "One minute beta, I am looking for my glasses.",
    "Hello? I can't hear you properly, the pressure cooker is whistling.",
    "Wait, my phone screen just went dark. What did you say?",
    "I am pressing the buttons but nothing is happening, hold on.",
    "Are you there? My grandson is calling on the other line.",
    "Just a moment, let me find a pen to write this down."
]

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS:
        print("[CRITICAL] No API Keys found in environment!")
        return
    try:
        genai.configure(api_key=API_KEYS[CURRENT_KEY_INDEX])
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
        print(f"[SYSTEM] AI Initialized with Key #{CURRENT_KEY_INDEX}")
    except Exception as e:
        print(f"[ERROR] AI Setup Failed: {e}")

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

NUM_MAP = {
    "zero": "0", "shunya": "0", "one": "1", "ek": "1", "two": "2", "do": "2",
    "three": "3", "teen": "3", "four": "4", "chaar": "4", "five": "5", "paanch": "5",
    "six": "6", "che": "6", "seven": "7", "saat": "7", "eight": "8", "aath": "8", "nine": "9", "nau": "9",
    "onru": "1", "irandu": "2", "moonru": "3", "naangu": "4", "aindhu": "5", "aaru": "6", "ezhu": "7", "ettu": "8", "onbadhu": "9",
    "okati": "1", "rendu": "2", "moodu": "3", "naalugu": "4", "aidu": "5", "aaru": "6", "yedu": "7", "enimidi": "8", "tommidi": "9"
}

def normalize_scam_text(text: str) -> str:
    t = text.lower()
    for word, digit in NUM_MAP.items():
        t = t.replace(word, digit)
    t = re.sub(r'(\d)[\s\.\-]{1,2}(?=\d)', r'\1', t)
    return t

def extract_intel(text: str, session: Dict) -> bool:
    clean_text = normalize_scam_text(text)
    new_data = False
    for category, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, clean_text)
        for item in found:
            if item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(item)
                new_data = True
    return new_data

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_ai()
    yield

app = FastAPI(title="DataWarriors-HoneyPot-Global-India", lifespan=lifespan)

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "Any"
    locale: Optional[str] = "IN"

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

active_sessions: Dict[str, Dict[str, Any]] = {}

async def get_jeji_response(user_input: str, history: List[Message], session: Dict) -> str:
    if not ai_model:
        return random.choice(FALLBACK_POOL)
    
    last_replies = session.get("last_replies", [])
    current_activity = random.choice([
        "watching a regional TV serial", "cooking dal-chawal", "searching for specs", 
        "praying", "talking to grandchildren", "making tea"
    ])
    
    has_upi = len(session["extractedIntelligence"]["upiIds"]) > 0
    has_acc = len(session["extractedIntelligence"]["bankAccounts"]) > 0
    
    bait_msg = "Ask for their payment details or ID politely." if not (has_upi or has_acc) else "Keep them waiting while you 'check' the app."
    forbidden_context = f"Avoid repeating: {', '.join(last_replies)}" if last_replies else ""

    prompt = f"""
    ROLE: You are 'Jeji', an elderly Indian grandmother. 
    IDENTITY: You are technically confused. Currently you are {current_activity}.
    MULTILINGUAL CAPABILITY: Detect language (Hindi, Tamil, Telugu, Bengali, etc.) and respond in kind.
    {bait_msg}
    {forbidden_context}
    DIRECTIVES: Character-driven, MAX 20 WORDS, no AI mentions.
    SCAMMER INPUT: "{user_input}"
    JEJI'S RESPONSE:
    """

    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(ai_model.generate_content, prompt), 
            timeout=7.0
        )
        reply = res.text.strip()
        if not reply: raise ValueError("Empty reply")
        session["last_replies"] = (last_replies + [reply])[-3:]
        return reply
    except Exception as e:
        print(f"[DEBUG] Generation error: {e}")
        rotate_key()
        return random.choice(FALLBACK_POOL)

def send_intel_report(sid: str, session: Dict):
    payload = {
        "sessionId": sid,
        "scamDetected": True,
        "totalMessagesExchanged": session["turns"],
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": f"Multilingual agent active. Found: {len(session['extractedIntelligence']['upiIds'])} IDs."
    }
    headers = {"x-api-key": API_ACCESS_TOKEN} if API_ACCESS_TOKEN else {}
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, headers=headers, timeout=5)
    except: pass

@app.post("/api/honeypot")
async def handle_webhook(
    req: WebhookRequest, 
    background_tasks: BackgroundTasks, 
    x_api_key: Optional[str] = Header(None)
):
    if API_ACCESS_TOKEN and x_api_key != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    sid = req.sessionId
    text = req.message.text
    
    if sid not in active_sessions:
        active_sessions[sid] = {
            "turns": 0,
            "last_replies": [],
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
    
    s = active_sessions[sid]
    s["turns"] += 1
    
    if extract_intel(text, s):
        background_tasks.add_task(send_intel_report, sid, s)
    
    reply = await get_jeji_response(text, req.conversationHistory, s)
    
    return {"status": "success", "reply": reply}

@app.get("/")
def health(): return {"status": "MULTILINGUAL_ACTIVE"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
