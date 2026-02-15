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

# --- Configuration and Keys ---
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

# --- Models ---
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

# --- Logic & Patterns ---
INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

SCAM_TRIGGERS = ["otp", "urgent", "blocked", "verify", "compromised", "winner", "cashback", "kyc"]

FALLBACK_REPLIES = [
    "Beta, I am looking for my reading glasses. One minute...",
    "The screen is very dark, how do I see the number?",
    "Wait, the pressure cooker is whistling, I can't hear you!",
    "My grandson told me not to talk to strangers, but you sound nice.",
    "Which bank did you say? My SBI or my HDFC?",
    "I am writing it down, please speak slowly."
]

RANDOM_ACTIVITIES = ["knitting a sweater", "drinking hot chai", "watering the Tulsi plant", "cleaning spectacles"]

# --- Core Functions ---

def scan_for_intel(text: str, session: Dict):
    phones = re.findall(INTEL_PATTERNS["phoneNumbers"], text)
    for category, regex in INTEL_PATTERNS.items():
        found = re.findall(regex, text)
        for item in found:
            if category == "bankAccounts" and item in phones: continue
            if item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(item)

async def generate_persona_reply(user_input: str, session: Dict, history: List[Message]) -> str:
    if ai_model is None: return random.choice(FALLBACK_REPLIES)
    
    # Avoid repetition by passing last 3 bot replies to the prompt
    recent_bot_context = ", ".join(session["reply_history"][-3:])
    activity = random.choice(RANDOM_ACTIVITIES)
    
    prompt = f"""
    Role: Jeji, a 68-year-old retired Indian grandmother.
    Context: You are {activity}. A person is messaging you: "{user_input}"
    Strict Constraints:
    1. Do NOT repeat these previous lines: [{recent_bot_context}]
    2. Be confused, slow, and polite. 
    3. Ask them to clarify their name or office location to waste time.
    4. Keep response under 25 words.
    5. Reply in the same language they used (English/Hindi/etc).
    """

    try:
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        reply = response.text.strip()
        
        # Validation against repetitive loops
        if not reply or any(prev.lower() in reply.lower() for prev in session["reply_history"][-2:]):
            return random.choice([r for r in FALLBACK_REPLIES if r not in session["reply_history"]])
        
        return reply
    except Exception:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

def dispatch_final_report(session_id: str, session_data: Dict):
    """Submits final analysis following structure in [cite: 109-122]"""
    duration = int(time.time() - session_data["startTime"])
    
    payload = {
        "sessionId": session_id,
        "status": "success", # [cite: 143]
        "scamDetected": session_data["is_scam"], # [cite: 143]
        "totalMessagesExchanged": session_data["turns"],
        "extractedIntelligence": session_data["extractedIntelligence"], # [cite: 143]
        "engagementMetrics": { # [cite: 143]
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": session_data["turns"]
        },
        "agentNotes": f"Jeji persona active. Wasted {duration} seconds. Scanned {session_data['turns']} turns."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception as e:
        print(f"Final Report Error: {e}")

# --- API Endpoints ---

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
            "reply_history": [],
            "reported": False,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    # Update detection and extraction [cite: 606, 618]
    if any(kw in msg_text.lower() for kw in SCAM_TRIGGERS):
        session["is_scam"] = True
    
    scan_for_intel(msg_text, session)
    
    # Generate non-repetitive reply [cite: 55, 620]
    reply = await generate_persona_reply(msg_text, session, req.conversationHistory)
    session["reply_history"].append(reply)

    # Automatically submit report at the 10th turn [cite: 57, 109]
    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)

    return {"status": "success", "reply": reply} # [cite: 101-106]

active_sessions: Dict[str, Dict] = {}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
