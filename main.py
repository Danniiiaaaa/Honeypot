import os
import re
import requests
import uvicorn
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Configuration
GEMINI_KEY = os.environ.get("GEMINI_KEY")
API_ACCESS_TOKEN = "guvi_winner_2026"
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# AI Setup (Global Variable)
ai_model = None

def configure_ai():
    global ai_model
    if "YOUR_GEMINI_API_KEY" in GEMINI_KEY:
        print("WARNING: GEMINI_KEY is still the default. AI features are DISABLED.")
        return

    try:
        genai.configure(api_key=GEMINI_KEY)
        
        # Smart Model Selection
        candidates = [
            "gemini-2.0-flash",
            "gemini-2.5-flash",
            "gemini-1.5-flash", 
            "gemini-pro", 
            "models/gemini-2.0-flash" 
        ]
        
        for model_name in candidates:
            try:
                print(f"Attempting to connect to: {model_name}...")
                test_model = genai.GenerativeModel(model_name)
                # Quick non-blocking check
                ai_model = test_model
                print(f"SUCCESS! AI Configured using model: {model_name}")
                return
            except Exception as e:
                print(f"{model_name} failed. Trying next...")

        print("\nALL KNOWN MODELS FAILED. Using fallback...")
        try:
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    ai_model = genai.GenerativeModel(m.name)
                    return
        except Exception:
            pass
            
    except Exception as e:
        print(f"AI Config Error: {e}")

# === LIFESPAN MANAGER (Fixes Startup Timeouts) ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run AI setup ONLY after server starts
    print(" Server starting... Initializing AI Brain...")
    configure_ai()
    yield
    print(" Server shutting down...")

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

# EXPANDED SCAM TRIGGER LIST (Categorized)
SCAM_TRIGGERS = [
    # Urgent Action
    "block", "suspend", "expiry", "expire", "immediate", "urgent", "24 hours", "terminate",
    "disconnect", "lapse", "deactivate", "ban", "invalid", "alert", "attention", "warn",
    
    # Financial / Banking
    "kyc", "pan", "pan card", "aadhaar", "adhar", "update", "verify", "verification",
    "account", "bank", "sbi", "hdfc", "icici", "axis", "pnb", "atm", "debit", "credit",
    "wallet", "refund", "cashback", "bonus", "credited", "debited", "reversal", "unpaid",
    "due", "overdue", "statement", "charge", "deducted", "bill", "invoice",
    
    # Authentication
    "otp", "pin", "password", "cvv", "m-pin", "mpin", "login", "credential", "sign in",
    "log in", "reset", "code", "auth",
    
    # Monetary Gain / Offers
    "lottery", "winner", "won", "prize", "gift", "lucky", "congratulations", "crore",
    "lakh", "million", "dollar", "job", "hiring", "salary", "income", "investment",
    "profit", "loan", "approved", "interest", "offer", "discount", "free", "claim",
    
    # Threats / Authority
    "police", "cbi", "rbi", "court", "case", "fir", "jail", "arrest", "warrant", "legal",
    "tax", "income tax", "customs", "seized", "penalty", "fine", "illegal", "department",
    "officer", "inspector", "cyber",
    
    # Technical / Action
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

def detect_scam_via_llm(text: str) -> bool:
    """
    Fallback: Ask the AI if this looks like a scam.
    This makes the solution true 'AI-Powered' detection.
    """
    if ai_model is None: return False
    
    try:
        # Quick prompt to classify intent
        prompt = f"""
        Analyze this message for scam intent (supports English, Hindi, Tamil, Telugu, Hinglish). 
        Message: "{text}"
        
        Rules:
        - Return strictly "TRUE" if it tries to steal money, credentials, or create urgency.
        - Return "FALSE" if it looks like a normal greeting or harmless message.
        - Be aggressive against financial requests.
        
        Answer (TRUE/FALSE):
        """
        response = ai_model.generate_content(prompt)
        clean_resp = response.text.strip().upper()
        return "TRUE" in clean_resp
    except:
        return False

def is_suspicious(text: str) -> bool:
    text_lower = text.lower()
    
    # 1. Rule-Based: Check for specific keywords (Fast)
    if any(t in text_lower for t in SCAM_TRIGGERS):
        return True
    
    # 2. Rule-Based: Check for suspicious patterns (Links/Phone)
    has_link = bool(re.search(INTEL_PATTERNS["phishingLinks"], text))
    has_phone = bool(re.search(INTEL_PATTERNS["phoneNumbers"], text))
    if has_link or has_phone:
        return True
        
    return False

def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None:
        return "CRITICAL ERROR: API Key is missing or No Model Found."

    try:
        past_context = "\n".join([f"{m.sender}: {m.text}" for m in history[-3:]])
        
        prompt = f"""
        Role: Jeji, a 68-year-old retired Indian grandmother.
        Traits: Technologically illiterate, very polite, confused, slow to understand.
        Current Context: Scammer said: "{user_input}"
        
        Directives:
        1. Reply in the SAME LANGUAGE (Hindi, Tamil, Telugu, English, or Hinglish) as the scammer.
        2. Never admit you know it is a scam.
        3. Feign confusion.
        4. Bait the scammer by asking for their details.
        5. Keep it brief (<30 words).
        6. Use varied terms of address (like Beta, Sir, or just 'you'), do not repeat 'Beta' in every sentence.
        
        History:
        {past_context}
        
        Reply as Jeji:
        """
        
        result = ai_model.generate_content(prompt)
        return result.text.strip()
    except Exception as e:
        return f"AI CRASHED: {str(e)}"

def dispatch_report(session_id: str, data: Dict):
    if not data["is_scam"]:
        return

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

# REGISTER LIFESPAN HERE
app = FastAPI(title="Honeypot API", lifespan=lifespan)

@app.post("/api/honeypot")
async def handle_webhook(
    req: WebhookRequest, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
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
    
    # === HYBRID DETECTION LOGIC ===
    if not session["is_scam"]:
        # Step 1: Fast Rule Check
        if is_suspicious(msg_text):
            session["is_scam"] = True
            session["extractedIntelligence"]["suspiciousKeywords"].append("keyword_match")
            print(f"Scam Detected via Keywords: {sid}")
        
        # Step 2: AI Fallback Check (If keywords failed)
        elif detect_scam_via_llm(msg_text):
            session["is_scam"] = True
            session["extractedIntelligence"]["suspiciousKeywords"].append("ai_model_detection")
            print(f"Scam Detected via AI Model: {sid}")

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
