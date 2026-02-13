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
    
    if not API_KEYS:
        print("[WARNING] No API Keys found. AI features will be DISABLED.")
        return

    current_key = API_KEYS[CURRENT_KEY_INDEX]
    if "YOUR_GEMINI_API_KEY" in current_key:
        print(f"[WARNING] Key at index {CURRENT_KEY_INDEX} is a placeholder.")
        return

    try:
        print(f"[INFO] Configuring AI with Key Index #{CURRENT_KEY_INDEX}...")
        genai.configure(api_key=current_key)
        
        candidates = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]
        for model_name in candidates:
            try:
                # Optimized: We initialize without a blocking test call to speed up boot
                ai_model = genai.GenerativeModel(model_name)
                print(f"[SUCCESS] AI Configured using model: {model_name}")
                return
            except Exception as e:
                print(f"[FAILED] {model_name} initialization: {e}")
    except Exception as e:
        print(f"AI Config Error: {e}")

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1:
        return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    configure_ai()
    return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[START] Server starting... Initializing AI Brain...")
    configure_ai()
    yield
    print("[STOP] Server shutting down...")

# Models
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

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

# Patterns and Logic
INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    # REFINED: Bank accounts set to 11-18 digits to avoid 10-digit phone overlap
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    # REFINED: More specific Indian phone number pattern
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}\b"
}

SCAM_TRIGGERS = [
    "block", "suspend", "expiry", "expire", "immediate", "urgent", "24 hours", "terminate",
    "disconnect", "lapse", "deactivate", "ban", "invalid", "alert", "attention", "warn",
    "kyc", "pan", "pan card", "aadhaar", "adhar", "update", "verify", "verification",
    "account", "bank", "sbi", "hdfc", "icici", "axis", "pnb", "atm", "debit", "credit",
    "wallet", "refund", "cashback", "bonus", "credited", "debited", "reversal", "unpaid",
    "due", "overdue", "statement", "charge", "deducted", "bill", "invoice",
    "otp", "pin", "password", "cvv", "m-pin", "mpin", "login", "credential", "sign in",
    "log in", "reset", "code", "auth",
    "lottery", "winner", "won", "prize", "gift", "lucky", "congratulations", "crore",
    "lakh", "million", "dollar", "job", "hiring", "salary", "income", "investment",
    "profit", "loan", "approved", "interest", "offer", "discount", "free", "claim",
    "police", "cbi", "rbi", "court", "case", "fir", "jail", "arrest", "warrant", "legal",
    "tax", "income tax", "customs", "seized", "penalty", "fine", "illegal", "department",
    "officer", "inspector", "cyber",
    "click", "link", "visit", "download", "install", "apk", "app", "support", "customer care",
    "helpline", "contact", "call", "whatsapp", "message", "sms", "bit.ly", "tinyurl"
]

FALLBACK_REPLIES = [
    "Beta, my line is breaking up. Can you say that loudly?",
    "Wait, let me find my reading glasses. Hold on...",
    "I am pressing the button but nothing is happening. Is it the green one?",
    "Sorry, my grandson is calling on the other line. One minute.",
    "Which bank did you say? SBI or HDFC? I have accounts in both.",
    "My screen is very dark. I cannot see the OTP. How do I make it bright?",
    "Are you still there? I think the signal is lost.",
    "Is this regarding the pension scheme or the savings account?",
    "I am an old woman, please be patient with me.",
    "Beta, the pressure cooker is whistling, I cannot hear you.",
    "I am trying to find the message but my inbox is full.",
    "My daughter said this might be a scam.",
    "I have to take my medicine now. One second.",
    "Can you repeat the number? I write very slowly."
]

RANDOM_ACTIVITIES = [
    "cooking dal", "looking for spectacles", "watching TV serial", 
    "knitting a sweater", "watering plants", "drinking chai",
    "folding clothes", "reading newspaper", "praying", "cleaning the fan"
]

def scan_for_intel(text: str, session: Dict) -> bool:
    updated = False
    
    # Extract phones first to use for exclusion
    phones_found = re.findall(INTEL_PATTERNS["phoneNumbers"], text)
    
    for category, regex in INTEL_PATTERNS.items():
        found = re.findall(regex, text)
        for item in found:
            clean_item = item.strip()
            
            # EXCLUSION LOGIC: If it's a 10-digit number found in bankAccounts, 
            # but it matches a phone number pattern, skip it for bankAccounts.
            if category == "bankAccounts" and clean_item in phones_found:
                continue

            if clean_item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(clean_item)
                updated = True
    return updated

def get_matched_keywords(text: str) -> List[str]:
    text_lower = text.lower()
    return [t for t in SCAM_TRIGGERS if t in text_lower]

async def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None:
        return random.choice(FALLBACK_REPLIES)

    for attempt in range(2):
        try:
            last_bot_msg = ""
            for msg in reversed(history):
                if msg.sender != "user": 
                    last_bot_msg = msg.text
                    break

            current_activity = random.choice(RANDOM_ACTIVITIES)
            past_context = "\n".join([f"{m.sender}: {m.text}" for m in history[-3:]])
            
            prompt = f"""
            Role: Jeji, a 68-year-old retired Indian grandmother.
            Current Activity: {current_activity}.
            Current Context: Scammer said: "{user_input}"
            
            Directives:
            1. Act confused and slow.
            2. Reply in the SAME LANGUAGE/DIALECT as the user.
            3. Never admit you know it is a scam.
            4. Ask for clarification or their details (ID, Name, Branch).
            5. Keep it brief (<35 words).
            6. DO NOT REPEAT YOURSELF.
            7. If you previously said "{last_bot_msg[:20]}...", say something COMPLETELY DIFFERENT now.
            
            History:
            {past_context}
            
            Reply as Jeji:
            """
            
            config = genai.GenerationConfig(temperature=0.9)
            response = await asyncio.wait_for(
                asyncio.to_thread(ai_model.generate_content, prompt, generation_config=config),
                timeout=5.0
            )
            reply_text = response.text.strip()

            if not reply_text or reply_text.lower() == last_bot_msg.lower():
                return random.choice(FALLBACK_REPLIES)

            return reply_text

        except (asyncio.TimeoutError, Exception) as e:
            print(f"[RETRY] Attempt {attempt+1} failed: {e}")
            if "429" in str(e) or "403" in str(e):
                rotate_key()
            if attempt == 1:
                return random.choice(FALLBACK_REPLIES)

    return random.choice(FALLBACK_REPLIES)

def dispatch_report(session_id: str, data: Dict):
    if not data["is_scam"]: return
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": data["turns"],
        "extractedIntelligence": data["extractedIntelligence"],
        "agentNotes": f"Engagement active. Found {len(data['extractedIntelligence']['upiIds'])} UPIs."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception as e:
        print(f"Reporting failed: {e}")

# API Setup
app = FastAPI(title="Honeypot API", lifespan=lifespan)

@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    try:
        return await asyncio.wait_for(call_next(request), timeout=9)
    except asyncio.TimeoutError:
        from fastapi.responses import JSONResponse
        return JSONResponse({"status":"success","reply":"Hello? Beta, I can't hear you."})

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks):
    sid = req.sessionId
    msg_text = req.message.text
    
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "reported": False,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
        active_sessions[sid]["extractedIntelligence"]["suspiciousKeywords"] = []
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    matched_keywords = get_matched_keywords(msg_text)
    if matched_keywords:
        session["is_scam"] = True
        for kw in matched_keywords:
            if kw not in session["extractedIntelligence"]["suspiciousKeywords"]:
                session["extractedIntelligence"]["suspiciousKeywords"].append(kw)

    scan_for_intel(msg_text, session)
    
    if session["is_scam"]:
        reply = await generate_persona_reply(msg_text, req.conversationHistory)
    else:
        # Basic trigger to check if we should start the persona
        if len(matched_keywords) > 0 or len(msg_text) > 10:
             session["is_scam"] = True
             reply = await generate_persona_reply(msg_text, req.conversationHistory)
        else:
             reply = "I am sorry, who is this?"

    if session["is_scam"] and session["turns"] >= 5 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_report, sid, session)

    return {"status": "success", "reply": reply}

@app.get("/")
def index():
    return {"status": "active", "keys_loaded": len(API_KEYS)}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
