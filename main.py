import os
import re
import time
import random
import requests
import uvicorn
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel

API_KEY = os.getenv("HONEYPOT_API_KEY", "abcd1234")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI(title="Adaptive Honeypot API")

INTEL_PATTERNS = {
    "phoneNumbers": r"\+?\d[\d\-\s]{8,15}\d",
    "phishingLinks": r"https?://[^\s]+",
    "bankAccounts": r"\b\d{11,18}\b",
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
}

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

active_sessions: Dict[str, Dict] = {}

def clean_text(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}")

def classify_scam(text: str) -> str:
    lower = text.lower()
    if any(k in lower for k in ["otp", "account", "blocked", "kyc"]):
        return "bank"
    if any(k in lower for k in ["cashback", "reward", "winner"]):
        return "reward"
    if any(k in lower for k in ["investment", "profit", "crypto", "returns"]):
        return "investment"
    if any(k in lower for k in ["click", "link", "offer"]):
        return "phishing"
    return "generic"

def detect_scam(text: str) -> bool:
    suspicious = [
        "urgent","verify","blocked","otp","limited",
        "reward","claim","transfer","refund","payment"
    ]
    return any(w in text.lower() for w in suspicious)

def extract_intel(text: str, session: Dict):
    for category, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            cleaned = clean_text(match)
            if cleaned not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(cleaned)

def generate_probe(session: Dict, text: str) -> str:
    scam_type = session["scamType"]
    intel = session["extractedIntelligence"]
    lower = text.lower()

    if not intel["phoneNumbers"]:
        return "Before I proceed, what is your official callback or WhatsApp number?"

    if not intel["phishingLinks"] and scam_type in ["bank", "phishing", "reward"]:
        return "Can you send the official website link again so I can verify it?"

    if not intel["emailAddresses"]:
        return "Can you send the instructions from your official email address?"

    if not intel["upiIds"] and any(k in lower for k in ["payment","transfer","upi"]):
        return "My bank app is asking for payee verification. What is the full UPI ID with registered name?"

    if not intel["bankAccounts"] and any(k in lower for k in ["reference","transaction","case"]):
        return "Can you share the case or reference number associated with this?"

    context_questions = []

    if "otp" in lower:
        context_questions.append("I just received a code. Should I enter it on the website or reply here?")

    if "payment" in lower:
        context_questions.append("Before sending money, can you confirm the exact UPI ID and callback number again?")

    if "link" in lower:
        context_questions.append("The website looks slightly different from my bank’s usual domain. Can you confirm it is official?")

    type_specific = {
        "bank": [
            "Which branch are you calling from?",
            "Is there an official case ID I should note?",
            "Can you confirm your employee ID?"
        ],
        "reward": [
            "Where can I verify this reward officially?",
            "Is there a support contact for this cashback offer?",
            "Will I receive confirmation after claiming?"
        ],
        "phishing": [
            "Does this offer appear on your main homepage?",
            "Is there an official support email listed?",
            "Can you resend the complete verification link?"
        ],
        "investment": [
            "Is your company registered officially?",
            "Can you share your office address?",
            "Is there a regulatory registration number?"
        ],
        "generic": [
            "Is there another contact number in case this line disconnects?",
            "Should I confirm this with your senior officer?",
            "Will I receive SMS confirmation after this?"
        ]
    }

    options = context_questions + type_specific.get(scam_type, []) + type_specific["generic"]

    return random.choice(options)

def submit_final_report(session_id: str, session: Dict):
    duration = int(time.time() - session["startTime"])

    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session["is_scam"],
        "totalMessagesExchanged": session["turns"] * 2,
        "extractedIntelligence": session["extractedIntelligence"],
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": session["turns"]
        },
        "agentNotes": f"ScamType={session['scamType']} Extracted={session['extractedIntelligence']}"
    }

    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except Exception:
        pass

@app.post("/api/honeypot")
async def honeypot(
    req: WebhookRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    sid = req.sessionId

    if sid not in active_sessions:
        active_sessions[sid] = {
            "is_scam": False,
            "scamType": classify_scam(req.message.text),
            "turns": 0,
            "startTime": time.time(),
            "reported": False,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }

    session = active_sessions[sid]
    session["turns"] += 1

    if detect_scam(req.message.text):
        session["is_scam"] = True

    extract_intel(req.message.text, session)

    reply = generate_probe(session, req.message.text)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(submit_final_report, sid, session)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
