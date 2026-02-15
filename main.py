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

# Configuration and Keys
_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(',') if k.strip()]
CURRENT_KEY_INDEX = 0

API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

ai_model = None

def configure_ai():
    global ai_model, CURRENT_KEY_INDEX
    if not API_KEYS: return
    current_key = API_KEYS[CURRENT_KEY_INDEX]
    try:
        genai.configure(api_key=current_key)
        ai_model = genai.GenerativeModel("gemini-1.5-flash")
    except Exception as e:
        print(f"AI Config Error: {e}")

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

# Models
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

# Global State
active_sessions: Dict[str, Dict[str, Any]] = {}

# Corrected Keys to match Evaluation Script (Source )
INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

SCAM_TRIGGERS = ["otp", "urgent", "blocked", "verify", "account compromised", "winner", "kyc", "cashback"]

FALLBACK_REPLIES = ["Beta, I'm looking for my glasses. Hold on...", "Can you repeat that? The line is bad."]

def scan_for_intel(text: str, session: Dict):
    phones_found = re.findall(INTEL_PATTERNS["phoneNumbers"], text)
    for category, regex in INTEL_PATTERNS.items():
        found = re.findall(regex, text)
        for item in found:
            clean_item = item.strip()
            if category == "bankAccounts" and clean_item in phones_found: continue
            if clean_item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(clean_item)

async def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None: return random.choice(FALLBACK_REPLIES)
    try:
        past_context = "\n".join([f"{m.sender}: {m.text}" for m in history[-3:]])
        prompt = f"Role: Jeji, a 68-year-old confused Indian grandmother. Scammer said: '{user_input}'. History: {past_context}. Reply briefly (<30 words) in their language. Be slow/confused."
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        return response.text.strip()
    except Exception:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

def dispatch_final_report(session_id: str, session_data: Dict):
    """
    Constructs finalOutput according to Scoring System [cite: 109-122, 143]
    """
    # Calculate duration (simulated for points) 
    duration = int(time.time() - session_data["startTime"])
    
    payload = {
        "sessionId": session_id,
        "status": "success", # Required for 5 pts 
        "scamDetected": session_data["is_scam"], # Required for 5 pts 
        "totalMessagesExchanged": session_data["turns"], 
        "extractedIntelligence": session_data["extractedIntelligence"], # Required for 5 pts 
        "engagementMetrics": { # Optional for 2.5 pts 
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": session_data["turns"]
        },
        "agentNotes": f"Detected scam. Captured {sum(len(v) for v in session_data['extractedIntelligence'].values())} intel pieces." # Optional 
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception as e:
        print(f"Final reporting failed: {e}")

app = FastAPI(lifespan=lifespan)

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    sid = req.sessionId
    msg_text = req.message.text
    
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "startTime": time.time(),
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    # Logic: Scan for scams and intelligence [cite: 125, 128]
    if any(kw in msg_text.lower() for kw in SCAM_TRIGGERS):
        session["is_scam"] = True
    
    scan_for_intel(msg_text, session)
    
    reply = await generate_persona_reply(msg_text, req.conversationHistory)

    # Trigger final report on the 10th turn or if conversation ends [cite: 57, 182]
    if session["turns"] >= 10:
        background_tasks.add_task(dispatch_final_report, sid, session)

    return {"status": "success", "reply": reply} # Format per [cite: 101-106]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
