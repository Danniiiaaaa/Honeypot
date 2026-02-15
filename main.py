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
# Comma-separated keys in env var for automatic rotation if 429 occurs [cite: 756-761]
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
        # Gemini 1.5 Flash selected for speed to ensure <30s response [cite: 181, 582]
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
# REFINED PATTERNS: Prevents 16-digit accounts from being flagged as 10-digit phones [cite: 130, 608]
INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    # FIX: (?<!\d) ensures no digit precedes the match, avoiding greedy overlap
    "phoneNumbers": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "emailAddresses": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

SCAM_TRIGGERS = ["otp", "urgent", "blocked", "verify", "compromised", "winner", "cashback", "kyc", "claim"]

# Persona-driven fallback responses [cite: 618-620]
FALLBACK_REPLIES = [
    "Beta, my reading glasses are missing. Can you read that again?",
    "Wait, I am pressing the button but it's not working. Is it the green one?",
    "Phone screen is so dark, I can't see anything. How to make it bright?",
    "Which bank did you say? SBI or HDFC? I have accounts in both.",
    "Beta, hold on, the pressure cooker is whistling!",
    "I am writing it down with my pen, please go slow."
]

RANDOM_ACTIVITIES = ["knitting", "drinking chai", "watering plants", "watching a TV serial", "praying"]

# --- Core Functions ---

def scan_for_intel(text: str, session: Dict):
    """Extracts and deduplicates intelligence across multiple categories [cite: 606-616]."""
    # 1. Bank Accounts first to handle longer numeric strings
    accounts = re.findall(INTEL_PATTERNS["bankAccounts"], text)
    for acc in accounts:
        if acc not in session["extractedIntelligence"]["bankAccounts"]:
            session["extractedIntelligence"]["bankAccounts"].append(acc.strip())

    # 2. Phone Numbers with safety exclusion for previously found accounts
    phones = re.findall(INTEL_PATTERNS["phoneNumbers"], text)
    for phone in phones:
        if not any(phone in acc for acc in session["extractedIntelligence"]["bankAccounts"]):
            if phone not in session["extractedIntelligence"]["phoneNumbers"]:
                session["extractedIntelligence"]["phoneNumbers"].append(phone.strip())

    # 3. Handle UPI, Links, and Emails
    for cat in ["upiIds", "phishingLinks", "emailAddresses"]:
        found = re.findall(INTEL_PATTERNS[cat], text)
        for item in found:
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item.strip())

async def generate_persona_reply(user_input: str, session: Dict) -> str:
    """Multilingual AI generation with baiting instructions to maximize extraction[cite: 55, 619, 624]."""
    if ai_model is None: return random.choice(FALLBACK_REPLIES)
    
    recent_history = ", ".join(session["reply_history"][-3:])
    activity = random.choice(RANDOM_ACTIVITIES)
    
    # Instruction: Bait for specific intel missing in current extracted sets
    baiting_hint = ""
    if not session["extractedIntelligence"]["upiIds"]:
        baiting_hint = "Ask them if you can pay/verify via UPI and what their ID is."
    elif not session["extractedIntelligence"]["phoneNumbers"]:
        baiting_hint = "Ask for their mobile number so your son can call them back."

    prompt = f"""
    Role: Jeji, a 68-year-old Indian grandmother. 
    Personality: Polite, slow with tech, talkative, easily worried.
    Current Activity: {activity}.
    Scammer Message: "{user_input}"
    
    Directives:
    1. Respond in the same language as the scammer (English, Hindi, or Hinglish).
    2. Act concerned but distracted. Do NOT repeat previous lines: [{recent_history}]
    3. Baiting: {baiting_hint} 
    4. Ask clarifying questions: "What is your full name?", "Which branch office?"
    5. Max 25 words. Stay in character!
    """

    try:
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        reply = response.text.strip()
        
        # Guard against AI repetition loops
        if not reply or any(prev.lower() in reply.lower() for prev in session["reply_history"][-2:]):
            return random.choice([r for r in FALLBACK_REPLIES if r not in session["reply_history"]])
        
        return reply
    except Exception:
        rotate_key()
        return random.choice(FALLBACK_REPLIES)

def dispatch_final_report(session_id: str, session_data: Dict):
    """Submits the finalOutput summary required for scoring [cite: 108-122, 143]."""
    duration = int(time.time() - session_data["startTime"])
    
    payload = {
        "sessionId": session_id,
        "status": "success", # 5 pts
        "scamDetected": session_data["is_scam"], # 5 pts
        "totalMessagesExchanged": session_data["turns"] * 2, 
        "extractedIntelligence": session_data["extractedIntelligence"], # 10 pts per unique type [cite: 130]
        "engagementMetrics": { # 2.5 pts
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": session_data["turns"]
        },
        "agentNotes": f"Persona Jeji maintained engagement for {duration}s. Strategy: Tech-illiterate grandmother baiting for UPI/Phone." # 2.5 pts
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception as e:
        print(f"Final Report Error: {e}")

# --- API Endpoints ---

app = FastAPI(lifespan=lifespan)
active_sessions: Dict[str, Dict] = {}

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    """Main webhook handling 10-turn multi-turn flow [cite: 56-60, 75-100]."""
    sid = req.sessionId
    msg_text = req.message.text
    
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "startTime": time.time(),
            "reply_history": [],
            "reported": False,
            "extractedIntelligence": {
                "phoneNumbers": [],
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "emailAddresses": []
            }
        }
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    # Update detection status [cite: 126]
    if any(kw in msg_text.lower() for kw in SCAM_TRIGGERS):
        session["is_scam"] = True
    
    scan_for_intel(msg_text, session)
    
    reply = await generate_persona_reply(msg_text, session)
    session["reply_history"].append(reply)

    # Submit final report on turn 10 [cite: 48, 57]
    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)

    # Compliant response structure [cite: 101-106]
    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
