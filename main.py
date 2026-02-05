import os
import re
import time
import requests
import uvicorn
import random
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

_raw_keys = os.environ.get("GEMINI_KEY")
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
        print(f"[WARNING] Key at index {CURRENT_KEY_INDEX} is a placeholder. AI disabled.")
        return

    try:
        print(f"[INFO] Configuring AI with Key Index #{CURRENT_KEY_INDEX}...")
        genai.configure(api_key=current_key)
        
        # Priority list of stable models
        candidates = [
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-pro"
        ]
        
        for model_name in candidates:
            try:
                ai_model = genai.GenerativeModel(model_name)
                print(f"[SUCCESS] AI Initialized using model: {model_name}")
                return
            except Exception as e:
                print(f"[FAILED] {model_name} initialization failed: {e}")

        # Fallback
        try:
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    if any(x in m.name for x in ['2.0', '2.5', 'exp', 'vision']):
                        continue
                    ai_model = genai.GenerativeModel(m.name)
                    print(f"[WARNING] Forcing connection to safe fallback: {m.name}")
                    return
        except Exception:
            pass
            
    except Exception as e:
        print(f"AI Config Error: {e}")

def rotate_key():
    global CURRENT_KEY_INDEX
    if len(API_KEYS) <= 1:
        print("[INFO] Only 1 key available. Cannot rotate.")
        return False
    
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    print(f"[ROTATION] Switching to API Key Index #{CURRENT_KEY_INDEX}")
    configure_ai()
    return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[START] Server starting... Initializing AI Brain...")
    configure_ai()
    yield
    print("[STOP] Server shutting down...")

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

active_sessions: Dict[str, Dict[str, Any]] = {}

INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{9,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}"
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
    "Are you from the main branch? I went there yesterday."
]

RANDOM_ACTIVITIES = [
    "cooking dal", "looking for spectacles", "watching TV serial", 
    "knitting a sweater", "watering plants", "drinking chai"
]

def scan_for_intel(text: str, session: Dict) -> bool:
    updated = False
    for category, regex in INTEL_PATTERNS.items():
        found = re.findall(regex, text)
        for item in found:
            clean_item = item.strip()
            if clean_item not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(clean_item)
                updated = True
    return updated

def get_matched_keywords(text: str) -> List[str]:
    text_lower = text.lower()
    return [t for t in SCAM_TRIGGERS if t in text_lower]

def detect_scam_via_llm(text: str) -> bool:
    # OPTIMIZATION: Disabled to reduce latency.
    return False

def is_suspicious(text: str) -> bool:
    text_lower = text.lower()
    if any(t in text_lower for t in SCAM_TRIGGERS): return True
    has_link = bool(re.search(INTEL_PATTERNS["phishingLinks"], text))
    has_phone = bool(re.search(INTEL_PATTERNS["phoneNumbers"], text))
    if has_link or has_phone: return True
    return False

# CHANGED TO ASYNC DEF FOR SPEED
async def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None:
        print("[CRITICAL] AI model is None during reply generation.")
        return random.choice(FALLBACK_REPLIES)

    # FAST RETRY: Only 1 retry to avoid timeouts
    for attempt in range(2):
        try:
            last_bot_msg = ""
            for msg in reversed(history):
                if msg.sender == "user": 
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
            
            config = genai.GenerationConfig(temperature=1.0)
            
            # ASYNC GENERATION FOR SPEED
            response = await ai_model.generate_content_async(prompt, generation_config=config)
            reply_text = response.text.strip()

            if reply_text.lower() == last_bot_msg.lower() or len(reply_text) < 5:
                print("[INFO] Loop detected! Using fallback reply.")
                return random.choice(FALLBACK_REPLIES)

            return reply_text

        except Exception as e:
            if any(err in str(e) for err in ["429", "403", "404"]):
                print(f"[WARNING] API Error ({e}). Rotating & Retrying immediately...")
                if rotate_key():
                    continue # Retry immediately (NO SLEEP)
            else:
                print(f"[ERROR] AI GENERATION CRASHED: {str(e)}")
                break 

    print("[ERROR] Max retries reached. Sending fallback.")
    return random.choice(FALLBACK_REPLIES)

def dispatch_report(session_id: str, data: Dict):
    if not data["is_scam"]: return
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": data["turns"],
        "extractedIntelligence": data["extractedIntelligence"],
        "agentNotes": f"Engagement active. Extracted {len(data['extractedIntelligence']['upiIds'])} payment identifiers."
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception as e:
        print(f"Report dispatch error: {e}")

app = FastAPI(title="Honeypot API", lifespan=lifespan)

@app.post("/api/honeypot")
async def handle_webhook(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    if x_api_key != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    sid = req.sessionId
    msg_text = req.message.text
    
    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "turns": 0,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }
        active_sessions[sid]["extractedIntelligence"]["suspiciousKeywords"] = []
    
    session = active_sessions[sid]
    session["turns"] += 1
    
    matched_keywords = get_matched_keywords(msg_text)
    if matched_keywords:
        if not session["is_scam"]: session["is_scam"] = True
        for kw in matched_keywords:
            if kw not in session["extractedIntelligence"]["suspiciousKeywords"]:
                session["extractedIntelligence"]["suspiciousKeywords"].append(kw)

    # REMOVED: detect_scam_via_llm call to reduce latency.

    new_intel = scan_for_intel(msg_text, session)
    
    if session["is_scam"]:
        # AWAIT IS REQUIRED NOW
        reply = await generate_persona_reply(msg_text, req.conversationHistory)
    else:
        reply = "I am sorry, who is this message for?"

    if session["is_scam"] and (new_intel or session["turns"] % 5 == 0):
        background_tasks.add_task(dispatch_report, sid, session)

    return {"status": "success", "reply": reply}

@app.get("/")
def index():
    return {"status": "active"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
