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
REPORTING_ENDPOINT = os.getenv(
    "REPORTING_ENDPOINT",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)

app = FastAPI(title="Elite Honeypot API")

INTEL_PATTERNS = {
    "phoneNumbers": r"\+?\d[\d\-\s]{8,15}\d",
    "phishingLinks": r"https?://[^\s]+",
    "bankAccounts": r"\b\d{11,18}\b",
    "upiIds": r"\b[\w\.-]{2,256}@[a-zA-Z]{2,64}\b",
    "emailAddresses": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "caseIds": r"\b(?:case|ref|reference|ticket)[\-\s:]?[A-Za-z0-9\-]{4,20}\b",
    "transactionIds": r"\bTXN[-_]?[A-Za-z0-9\-]{4,20}\b",
    "orderNumbers": r"\b(?:order|policy)[\-\s:]?[A-Za-z0-9\-]{5,20}\b"
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

def clean(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}")

def detect_scam(text: str) -> bool:
    keywords = [
        "urgent","verify","blocked","otp","limited",
        "reward","claim","transfer","refund","payment","kyc","click"
    ]
    return any(k in text.lower() for k in keywords)

def classify_scam(text: str) -> str:
    lower = text.lower()
    if "otp" in lower or "account" in lower:
        return "bank_fraud"
    if "cashback" in lower or "reward" in lower:
        return "upi_fraud"
    if "crypto" in lower or "investment" in lower:
        return "investment_scam"
    if "click" in lower or "link" in lower:
        return "phishing"
    return "generic"

def extract_intelligence(text: str, session: Dict):
    for key, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            value = clean(match)
            if value not in session["extractedIntelligence"][key]:
                session["extractedIntelligence"][key].append(value)

def identify_red_flags(text: str) -> List[str]:
    lower = text.lower()
    flags = []
    if "otp" in lower:
        flags.append("Requesting OTP over chat is a known fraud indicator.")
    if "urgent" in lower or "immediately" in lower:
        flags.append("Creating urgency is a common scam tactic.")
    if "transfer" in lower or "payment" in lower:
        flags.append("Advance payment requests for verification are suspicious.")
    if "click" in lower or "link" in lower:
        flags.append("Unverified links may lead to phishing attacks.")
    return flags

def generate_probe(session: Dict, text: str) -> str:
    intel = session["extractedIntelligence"]
    flags = identify_red_flags(text)
    probes = []

    if flags:
        probes.append(flags[0])

    if not intel["phoneNumbers"]:
        probes.append("Please provide your official callback number.")

    if not intel["emailAddresses"]:
        probes.append("Can you send confirmation from your official corporate email?")

    if not intel["phishingLinks"]:
        probes.append("What is the official website URL listed on your homepage?")

    if not intel["upiIds"]:
        probes.append("Kindly confirm the full UPI ID along with beneficiary name.")

    if not intel["bankAccounts"]:
        probes.append("Please provide the official case or transaction reference number.")

    probes.extend([
        "What is your employee ID and department?",
        "Can you share your branch address?",
        "Is this process documented on your official website?",
        "Will I receive written confirmation after verification?"
    ])

    for probe in probes:
        if probe not in session["asked"]:
            session["asked"].add(probe)
            return probe

    return random.choice(probes)

def submit_final_report(session_id: str, session: Dict):
    duration = int(time.time() - session["startTime"])

    payload = {
        "sessionId": session_id,
        "scamDetected": session["isScam"],
        "scamType": session["scamType"],
        "confidenceLevel": 0.95,
        "totalMessagesExchanged": session["turns"] * 2,
        "engagementDurationSeconds": duration,
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": "Scam detected using behavioral red-flag analysis and adaptive probing."
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

    if req.message.sender != "scammer":
        return {"status": "success", "reply": "Please clarify your message."}

    sid = req.sessionId

    if sid not in active_sessions:
        active_sessions[sid] = {
            "isScam": False,
            "scamType": classify_scam(req.message.text),
            "turns": 0,
            "startTime": time.time(),
            "reported": False,
            "asked": set(),
            "extractedIntelligence": {k: [] for k in INTEL_PATTERNS.keys()}
        }

    session = active_sessions[sid]
    session["turns"] += 1

    if detect_scam(req.message.text):
        session["isScam"] = True

    extract_intelligence(req.message.text, session)

    reply = generate_probe(session, req.message.text)

    if session["turns"] >= 10 and not session["reported"]:
        session["reported"] = True
        background_tasks.add_task(submit_final_report, sid, session)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
