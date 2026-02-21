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

active_sessions: Dict[str, Dict] = {}

def clean_text(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}")

def detect_scam(text: str) -> bool:
    return any(k in text.lower() for k in SCAM_KEYWORDS)

def extract_intelligence(text: str, session: Dict):
    for category, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            cleaned = clean_text(match)
            if cleaned not in session["extractedIntelligence"][category]:
                session["extractedIntelligence"][category].append(cleaned)

def adaptive_probe(session: Dict, text: str) -> str:
    intel = session["extractedIntelligence"]
    lower = text.lower()

    probes = []

    if not intel["phoneNumbers"]:
        probes.append("Before I proceed, can you confirm your official callback or WhatsApp number?")

    if not intel["phishingLinks"]:
        probes.append("I am getting a browser warning. Can you send the exact official website link again?")

    if not intel["emailAddresses"]:
        probes.append("Can you email the instructions from your official company email so I have proof?")

    if not intel["upiIds"]:
        probes.append("My bank app is asking for payee verification. What is the full UPI ID with registered name?")

    if not intel["bankAccounts"]:
        probes.append("Is there a reference or case number I should note for this transaction?")

    context_probes = []

    if "otp" in lower:
        context_probes.append("I just received a code. Should I enter it on the website or reply here?")

    if "payment" in lower or "upi" in lower:
        context_probes.append("Before sending money, can you confirm the exact UPI ID and callback number again?")

    if "link" in lower:
        context_probes.append("The page looks slightly different from my bank’s usual site. Can you confirm it is official?")

    all_options = context_probes + probes

    if not all_options:
        all_options = [
            "Should I confirm this with your senior officer as well?",
            "Is there another contact number in case this line disconnects?",
            "Will I receive an SMS confirmation after this process?"
        ]

    return random.choice(all_options)

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
        "agentNotes": f"Extracted: {session['extractedIntelligence']}"
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
            "turns": 0,
            "startTime": time.time(),
            "reported": False,
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }

    session = active_sessions[sid]
    session["turns"] += 1

    if detect_scam(req.message.text):
        session["is_scam"] = True

    extract_intelligence(req.message.text, session)

    reply = adaptive_probe(session, req.message.text)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(submit_final_report, sid, session)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
