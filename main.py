import os
import json
import re
import requests
import asyncio
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from google import genai

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
    client = genai.Client(api_key=key)
    return client

def get_client():
    global client
    if client is None:
        if not API_KEYS:
            return None
        client = genai.Client(api_key=API_KEYS[0])
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
    current_c = get_client()
    if current_c is None:
        return None

    for _ in range(len(API_KEYS)):
        try:
            response = await current_c.aio.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            return response.text
        except Exception:
            current_c = rotate_key()

    return None

@app.post("/api/honeypot")
async def honeypot(request: Request):
    if request.headers.get("x-api-key") != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    data = RequestBody(**body)

    msg = data.message.text.lower()
    scam_keywords = ["account blocked", "verify", "otp", "upi", "bank", "urgent", "suspend", "locked", "pin"]
    scam_detected = any(k in msg for k in scam_keywords)

    history_text = "\n".join([f"{m['sender']}: {m['text']}" for m in data.conversationHistory])

    if scam_detected:
        prompt = (
            "You are a normal, slightly confused human talking on chat. "
            "Continue the conversation naturally. Never reveal you are an AI.\n"
            f"{history_text}\nScammer: {data.message.text}\nYour reply:"
        )
        reply = await call_model(prompt)
        
        if reply is None:
            return {"status": "error", "reply": "Service temporarily unavailable"}

        intel_prompt = (
            "Extract scam intelligence from the conversation in valid JSON format only. "
            "Fields: bankAccounts (list), upiIds (list), phishingLinks (list), phoneNumbers (list), suspiciousKeywords (list).\n"
            f"Conversation:\n{history_text}\nScammer: {data.message.text}"
        )
        intel_raw = await call_model(intel_prompt)
        
        extracted_intel = {}
        if intel_raw:
            try:
                json_str = re.search(r'\{.*\}', intel_raw, re.DOTALL).group()
                extracted_intel = json.loads(json_str)
            except Exception:
                extracted_intel = {"raw_notes": "Failed to parse JSON"}

        payload = {
            "sessionId": data.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": len(data.conversationHistory) + 1,
            "extractedIntelligence": extracted_intel,
            "agentNotes": "Intelligence captured via Gemini 2.0 Flash"
        }

        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, lambda: requests.post(REPORTING_ENDPOINT, json=payload, timeout=5))
        except Exception:
            pass

    else:
        prompt = f"Respond naturally to this message: {data.message.text}"
        reply = await call_model(prompt)

        if reply is None:
            return {"status": "error", "reply": "Service busy"}

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
