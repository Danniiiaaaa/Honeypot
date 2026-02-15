from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import google.generativeai as genai
import re
import os
import time

app = FastAPI()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

sessions = {}

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list
    metadata: dict

def extract_phone_numbers(text):
    phones = re.findall(r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b', text)
    return list(set(phones))

def extract_account_numbers(text):
    accs = re.findall(r'\b\d{9,18}\b', text)
    result = []
    for a in accs:
        if not re.fullmatch(r'(?:\+91)?[6-9]\d{9}', a):
            result.append(a)
    return list(set(result))

def extract_upi(text):
    upi = re.findall(r'\b[\w.-]+@[\w.-]+\b', text)
    return list(set(upi))

def extract_links(text):
    links = re.findall(r'(https?://[^\s]+)', text)
    return list(set(links))

def extract_emails(text):
    mails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    return list(set(mails))

def ai_response(user_msg):
    model = genai.GenerativeModel("gemini-pro")
    out = model.generate_content(
        "You are a scam-honeypot. Respond with short, curious, non-revealing questions only.\nScammer: "
        + user_msg
    )
    return out.text.strip()

@app.post("/api/honeypot")
async def honeypot(data: HoneypotRequest):
    sid = data.sessionId
    scam_msg = data.message.text.strip()

    if sid not in sessions:
        sessions[sid] = {"turns": 1, "msgs": [], "intel": {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": []
        }}
    else:
        sessions[sid]["turns"] += 1

    sessions[sid]["msgs"].append({"sender": "scammer", "text": scam_msg})

    phones = extract_phone_numbers(scam_msg)
    accs = extract_account_numbers(scam_msg)
    upis = extract_upi(scam_msg)
    links = extract_links(scam_msg)
    mails = extract_emails(scam_msg)

    sessions[sid]["intel"]["phoneNumbers"].extend([p for p in phones if p not in sessions[sid]["intel"]["phoneNumbers"]])
    sessions[sid]["intel"]["bankAccounts"].extend([a for a in accs if a not in sessions[sid]["intel"]["bankAccounts"]])
    sessions[sid]["intel"]["upiIds"].extend([u for u in upis if u not in sessions[sid]["intel"]["upiIds"]])
    sessions[sid]["intel"]["phishingLinks"].extend([l for l in links if l not in sessions[sid]["intel"]["phishingLinks"]])
    sessions[sid]["intel"]["emailAddresses"].extend([e for e in mails if e not in sessions[sid]["intel"]["emailAddresses"]])

    reply = ai_response(scam_msg)

    sessions[sid]["msgs"].append({"sender": "user", "text": reply})

    if sessions[sid]["turns"] >= 10:
        final_out = {
            "sessionId": sid,
            "scamDetected": True,
            "totalMessagesExchanged": len(sessions[sid]["msgs"]),
            "extractedIntelligence": sessions[sid]["intel"],
            "agentNotes": "Scam conversation simulated and logged."
        }
        return final_out

    return {"status": "success", "reply": reply}

@app.get("/")
async def root():
    return {"status": "running"}
