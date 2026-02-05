import os
import re
import requests
import uvicorn
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager 

# Configuration
GEMINI_KEY = os.environ.get("GEMINI_KEY")
API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# AI Setup (Global Variable)
ai_model = None

def configure_ai():
    global ai_model
    # Check if key is the placeholder or empty
    if "YOUR_GEMINI_API_KEY" in GEMINI_KEY or not GEMINI_KEY:
        print("⚠️ WARNING: GEMINI_KEY is missing. AI features will be DISABLED.")
        return

    try:
        genai.configure(api_key=GEMINI_KEY)
        
        # We put 1.5-flash FIRST now, as it is the most stable Free Tier model.
        candidates = [
            "gemini-1.5-flash", 
            "gemini-2.0-flash",
            "gemini-2.5-flash",
            "gemini-pro", 
            "models/gemini-1.5-flash" 
        ]
        
        for model_name in candidates:
            try:
                print(f"🔄 Testing connection to: {model_name}...")
                test_model = genai.GenerativeModel(model_name)
                
                # CRITICAL FIX: We MUST generate content to prove quota exists
                test_model.generate_content("Test connection")
                
                # If we get here, it worked!
                ai_model = test_model
                print(f"✅ SUCCESS! AI Configured using model: {model_name}")
                return
            except Exception as e:
                print(f"❌ {model_name} failed: {e}")

        print("\n⚠️ ALL KNOWN MODELS FAILED. Using fallback...")
        try:
            # Last resort: grab the first available model from list_models
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    ai_model = genai.GenerativeModel(m.name)
                    print(f"⚠️ Forcing connection to fallback: {m.name}")
                    return
        except Exception:
            pass
            
    except Exception as e:
        print(f"AI Config Error: {e}")

# === LIFESPAN MANAGER ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Server starting... Initializing AI Brain...")
    configure_ai()
    yield
    print("🛑 Server shutting down...")

# Data Models
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

# In-memory storage
active_sessions: Dict[str, Dict[str, Any]] = {}

# Regex patterns for intelligence
INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{9,18}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&'()*+,;=]*)?",
    "phoneNumbers": r"(?:\+91[\-\s]?)?[6-9]\d{9}"
}

# SCAM TRIGGER LIST
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
    if ai_model is None: return False
    try:
        prompt = f"""
        Analyze this message for scam intent (supports English, Hindi, Tamil, Telugu, Hinglish). 
        Message: "{text}"
        Rules: Return strictly "TRUE" if it tries to steal money, credentials, or create urgency. Otherwise "FALSE".
        Answer (TRUE/FALSE):
        """
        response = ai_model.generate_content(prompt)
        clean_resp = response.text.strip().upper()
        return "TRUE" in clean_resp
    except:
        return False

def is_suspicious(text: str) -> bool:
    text_lower = text.lower()
    if any(t in text_lower for t in SCAM_TRIGGERS): return True
    has_link = bool(re.search(INTEL_PATTERNS["phishingLinks"], text))
    has_phone = bool(re.search(INTEL_PATTERNS["phoneNumbers"], text))
    if has_link or has_phone: return True
    return False

def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None:
        return "CRITICAL ERROR: AI Model failed to initialize. Check Render logs."

    try:
        past_context = "\n".join([f"{m.sender}: {m.text}" for m in history[-3:]])
        prompt = f"""
        Role: Jeji, a 68-year-old retired Indian grandmother.
        Traits: Technologically illiterate, very polite, confused, slow to understand.
        Current Context: Scammer said: "{user_input}"
        Directives:
        1. Reply in the SAME LANGUAGE as the scammer.
        2. Never admit you know it is a scam.
        3. Feign confusion.
        4. Bait the scammer by asking for their details.
        5. Keep it brief (<30 words).
        6. Use varied terms of address (like Beta, Sir, or just 'you'), do not repeat 'Beta'.
        History:
        {past_context}
        Reply as Jeji:
        """
        result = ai_model.generate_content(prompt)
        return result.text.strip()
    except Exception as e:
        return f"AI CRASHED: {str(e)}"

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

    if not session["is_scam"]:
        if detect_scam_via_llm(msg_text):
            session["is_scam"] = True
            session["extractedIntelligence"]["suspiciousKeywords"].append("AI_DETECTED_SUSPICIOUS_CONTENT")

    new_intel = scan_for_intel(msg_text, session)
    
    if session["is_scam"]:
        reply = generate_persona_reply(msg_text, req.conversationHistory)
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





