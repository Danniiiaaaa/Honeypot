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
        
        candidates = [
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-pro"
        ]
        
        for model_name in candidates:
            try:
                # We use the synchronous generate_content here, and we know it works.
                test_model = genai.GenerativeModel(model_name)
                test_model.generate_content("Test connection")
                ai_model = test_model
                print(f"[SUCCESS] AI Configured using model: {model_name}")
                return
            except Exception as e:
                print(f"[FAILED] {model_name} initialization failed: {e}")

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
    "Are you from the main branch? I went there yesterday.",
    "Hello? Are you still there? I think the signal is lost.",
    "My battery is showing low red line. Let me find the charger.",
    "Is this regarding the pension scheme or the savings account?",
    "I cannot hear you clearly, there is a lot of static.",
    "Can you call me back on the landline? This mobile is acting up.",
    "My spectacles are in the other room. Just a moment.",
    "Why are you asking for this code? Is it safe?",
    "I typed the number but it says 'Invalid Input'. What to do?",
    "Wait, the milk is boiling over! Hold on one second.",
    "I am an old woman, please be patient with me.",
    "Did you say your name was Rahul or Ramesh?",
    "I don't have my passbook with me right now.",
    "Can I go to the ATM and do this? It is near my house.",
    "Beta, the pressure cooker is whistling, I cannot hear you.",
    "Is this Mr. Sharma from the LIC office?",
    "My hands are shaking, I pressed the wrong button I think.",
    "Hold on, my neighbor Mrs. Gupta is at the door.",
    "I am trying to find the message but my inbox is full.",
    "Does this require an internet connection? My wifi is off.",
    "Please speak slowly, my hearing aid is not working well today.",
    "Are you calling about the fixed deposit maturity?",
    "I accidentally deleted the message. Can you send it again?",
    "My phone is very hot, I think it might explode.",
    "Do I need to go to the bank for this?",
    "My son told me not to share numbers with strangers.",
    "Is this about the electricity bill? I already paid it.",
    "Wait, I am looking for a pen to write this down.",
    "The screen is spinning round and round. What does that mean?",
    "Can you talk to my husband? He handles the money.",
    "I am in the middle of my evening prayers. Can you wait?",
    "My phone display is cracked, I cannot read the numbers.",
    "Are you the same person who called yesterday about the lottery?",
    "I don't remember my PIN number. Is it written on the card?",
    "Wait, the cat just jumped on the table!",
    "Can I do this tomorrow morning? It is very late.",
    "My phone is running out of balance.",
    "Is there a charge for this service?",
    "I think I received a message from the police too.",
    "Why is the bank calling from a personal number?",
    "Let me put on my speakerphone.",
    "I am pressing 'OK' but it goes back to the home screen.",
    "Do you know my branch manager, Mr. Patel?",
    "I am confused, which app should I open?",
    "My grandson usually helps me with this. He is in school.",
    "The letters are too small. I cannot read them.",
    "Is this mandatory? Can I opt out?",
    "My account balance is zero anyway.",
    "Wait, I am getting another call.",
    "Can you verify my address first?",
    "I don't have a debit card, only a passbook.",
    "Is this about the gold loan?",
    "My phone fell in water yesterday, the sound is low.",
    "I am eating lunch. Can you call in 1 hour?",
    "Did I win something? Is this a prize?",
    "I am afraid of doing this online. Can I come to the office?",
    "What is an OTP? Is it the 4 digit number?",
    "I think I entered the wrong password 3 times.",
    "The app is asking for an update. Should I click yes?",
    "My screen says 'Loading'. It is stuck.",
    "Can you send me a letter by post instead?",
    "I don't use Google Pay or PhonePe.",
    "My daughter said this might be a scam.",
    "Are you really from the bank? You sound young.",
    "I have to take my medicine now. One second.",
    "The keypad is not coming up on the screen.",
    "I am looking for my reading glasses in the drawer.",
    "Can you repeat the number? I write very slowly.",
    "Is this the same bank that is near the vegetable market?",
    "I don't have my chequebook handy.",
    "Why do you need my date of birth?",
    "My phone is very old, it doesn't have internet.",
    "The TV volume is too high, let me lower it.",
    "I am trying to find the SMS app.",
    "It says 'Network Error'. What should I do?",
    "Can you send the message in Hindi or Tamil?",
    "I am not comfortable sharing this over the phone.",
    "Let me ask my neighbor to help me.",
    "I pressed the red button by mistake.",
    "The phone is slipping from my hand.",
    "I am making tea, just one minute.",
    "Can you hold on? The doorbell is ringing.",
    "I don't understand these English words.",
    "Is this urgent? I was sleeping.",
    "My card is expired I think.",
    "I lost my purse yesterday with the card.",
    "Can I call you back on the official number?",
    "Who is this speaking again?",
    "My memory is very bad these days.",
    "I am trying to unlock my phone.",
    "The touch screen is not working properly.",
    "I am driving, wait.",
    "Are you the manager?",
    "I don't have any money to give you.",
    "Is this a government scheme?",
    "My phone is about to switch off."
]

RANDOM_ACTIVITIES = [
    "cooking dal", "looking for spectacles", "watching TV serial", 
    "knitting a sweater", "watering plants", "drinking chai",
    "folding clothes", "reading newspaper", "praying", "cleaning the fan"
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
    return False

def is_suspicious(text: str) -> bool:
    text_lower = text.lower()
    if any(t in text_lower for t in SCAM_TRIGGERS): return True
    has_link = bool(re.search(INTEL_PATTERNS["phishingLinks"], text))
    has_phone = bool(re.search(INTEL_PATTERNS["phoneNumbers"], text))
    if has_link or has_phone: return True
    return False

async def generate_persona_reply(user_input: str, history: List[Message]) -> str:
    if ai_model is None:
        print("[CRITICAL] AI model is None during reply generation.")
        return random.choice(FALLBACK_REPLIES)

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
            
            # FIXED: Using Synchronous call in a Thread to solve 404/Async bugs
            response = await asyncio.to_thread(ai_model.generate_content, prompt, generation_config=config)
            reply_text = response.text.strip()

            if reply_text.lower() == last_bot_msg.lower() or len(reply_text) < 5:
                print("[INFO] Loop detected! Using fallback reply.")
                return random.choice(FALLBACK_REPLIES)

            return reply_text

        except Exception as e:
            if any(err in str(e) for err in ["429", "403", "404"]):
                print(f"[WARNING] API Error ({e}). Attempting Key Rotation...")
                if rotate_key():
                    continue 
                else:
                    # If we only have 1 key and it fails, wait and retry once
                    print(f"[WARNING] Rotation failed (only 1 key). Retrying in 2s...")
                    await asyncio.sleep(2)
                    continue
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

    if not session["is_scam"]:
        if detect_scam_via_llm(msg_text):
            session["is_scam"] = True
            session["extractedIntelligence"]["suspiciousKeywords"].append("AI_DETECTED_SUSPICIOUS_CONTENT")

    new_intel = scan_for_intel(msg_text, session)
    
    if session["is_scam"]:
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
