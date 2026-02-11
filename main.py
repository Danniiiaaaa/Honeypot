import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from google.genai import Client
import requests

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
CURRENT_KEY_INDEX = 0
API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

client = None

def rotate_key():
    global CURRENT_KEY_INDEX, client
    if not API_KEYS:
        return None
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    key = API_KEYS[CURRENT_KEY_INDEX]
    client = Client(api_key=key)
    return client

def get_client():
    global client
    if client is None:
        if not API_KEYS:
            return None
        client = Client(api_key=API_KEYS[0])
    return client

class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: dict = None

app = FastAPI()

async def call_model(prompt):
    global client
    c = get_client()
    if c is None:
        return None
    for _ in range(len(API_KEYS)):
        try:
            r = c.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            return r.text
        except Exception:
            rotate_key()
    return None

@app.post("/api/honeypot")
async def honeypot(request: Request):
    headers = request.headers
    if headers.get("x-api-key") != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    data = RequestBody(**body)

    msg = data.message.text.lower()
    scam_keywords = ["account blocked", "verify", "otp", "upi", "bank", "urgent", "suspend", "locked", "pin"]
    scam_detected = any(k in msg for k in scam_keywords)

    if scam_detected:
        history = "\n".join([f"{m['sender']}: {m['text']}" for m in data.conversationHistory])
        prompt = f"You are a human. Continue the conversation naturally. Never reveal you're an AI.\nHistory:\n{history}\nScammer: {data.message.text}\nYour reply:"
        reply = await call_model(prompt)
        if reply is None:
            return {"status": "error", "reply": "All API keys failed"}

        intel_prompt = f"Extract scam intelligence from this conversation. Return JSON with fields: bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords.\nConversation:\n{history}\nScammer: {data.message.text}"
        intel_raw = await call_model(intel_prompt)
        if intel_raw is None:
            intel_raw = "{}"

        try:
            extracted_intel = eval(intel_raw)
        except:
            extracted_intel = {}

        payload = {
            "sessionId": data.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": len(data.conversationHistory) + 1,
            "extractedIntelligence": extracted_intel,
            "agentNotes": "Scam conversation handled"
        }

        try:
            requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
        except:
            pass

        return {"status": "success", "reply": reply}

    prompt = f"Respond as a normal human: {data.message.text}"
    reply = await call_model(prompt)
    if reply is None:
        return {"status": "error", "reply": "All API keys failed"}

    return {"status": "success", "reply": reply}
