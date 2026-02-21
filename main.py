import os
import re
import time
import random
import requests
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

API_KEY = os.getenv("HONEYPOT_API_KEY", "abcd1234")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

INTEL_PATTERNS = {
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "bankAccounts": r"\b\d{11,18}\b",
    "phishingLinks": r"(https?://[^\s]+)",
    "phoneNumbers": r"(\+?\d[\d\-\s]{8,15}\d)",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
}

SCAM_KEYWORDS = [
    "otp","urgent","blocked","verify","compromised",
    "winner","cashback","kyc","claim","refund",
    "payment","account","limited","offer"
]

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Dict] = None

app = FastAPI()
active_sessions: Dict[str, Dict] = {}

def clean(item):
    return item.strip().rstrip(".,;:!?)]}")

def scan_for_intel(text, session):
    for cat, pattern in INTEL_PATTERNS.items():
        found = re.findall(pattern, text)
        for item in found:
            item = clean(item)
            if cat == "upiIds" and "." in item.split("@")[-1]:
                if item not in session["extractedIntelligence"]["emailAddresses"]:
                    session["extractedIntelligence"]["emailAddresses"].append(item)
            if item not in session["extractedIntelligence"][cat]:
                session["extractedIntelligence"][cat].append(item)

def choose_question(session):
    intel = session["extractedIntelligence"]
    turn = session["turns"]

    questions = []

    if not intel["phoneNumbers"]:
        questions.append("Before I proceed, can you confirm your official callback or WhatsApp number so I can note it down?")

    if not intel["phishingLinks"]:
        questions.append("I’m seeing a warning on my screen. Can you send the exact official verification link again?")

    if not intel["emailAddresses"]:
        questions.append("Can you email me the instructions from your official email so I have written proof?")

    if not intel["upiIds"]:
        questions.append("My bank app is asking for payee confirmation. What is the full UPI ID with registered name?")

    if not intel["bankAccounts"]:
        questions.append("For verification, what is the transaction or reference number associated with this case?")

    fallback = [
        "Should I also confirm this with your senior officer before proceeding?",
        "Is there another contact number in case this line disconnects?",
        "Can you repeat the website link once more slowly?",
        "Do I need to enter the OTP on your website or reply here?",
        "Will I receive an SMS confirmation after this?"
    ]

    if questions:
        return random.choice(questions)

    return random.choice(fallback)

def generate_persona_reply(session, text):
    lower = text.lower()

    if any(k in lower for k in ["otp", "code"]):
        return "I just received something on my phone. Where exactly should I enter it?"

    if any(k in lower for k in ["payment","upi","transfer"]):
        return "Before I send anything, can you confirm the exact UPI ID and callback number again?"

    if any(k in lower for k in ["link","website","portal"]):
        return "The page looks slightly different from my bank’s site. Can you confirm this is official?"

    return choose_question(session)

def dispatch_final_report(session_id, session):
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
        "agentNotes": str(session["extractedIntelligence"])
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass

@app.post("/honeypot")
async def honeypot(req: WebhookRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    sid = req.sessionId
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

    if any(k in req.message.text.lower() for k in SCAM_KEYWORDS):
        session["is_scam"] = True

    scan_for_intel(req.message.text, session)

    reply = generate_persona_reply(session, req.message.text)
    session["reply_history"].append(reply)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(dispatch_final_report, sid, session)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
