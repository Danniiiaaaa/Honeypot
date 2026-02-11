import os
import json
import time
import random
import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
from google import genai

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
CURRENT_KEY_INDEX = 0

API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

client = genai.Client(api_key=API_KEYS[0])
app = FastAPI()


def rotate_key():
    global CURRENT_KEY_INDEX, client
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    client = genai.Client(api_key=API_KEYS[CURRENT_KEY_INDEX])


def ai_call(prompt: str):
    try:
        r = client.models.generate(model="gemini-1.5-flash", contents=prompt)
        return r.text.strip()
    except:
        rotate_key()
        r = client.models.generate(model="gemini-1.5-flash", contents=prompt)
        return r.text.strip()


def detect_scam(text: str):
    r = ai_call(f"Is this message a scam? Answer yes or no only. Message: {text}")
    return "yes" in r.lower()


def agent_reply(history: List[Dict], msg: str):
    h = ""
    for m in history:
        h += f"{m['sender']}: {m['text']}\n"
    h += f"scammer: {msg}\n"
    prompt = (
        "You are a confused Indian user. Never reveal you are AI. "
        "Continue the conversation naturally and make the scammer talk more.\n\n"
        f"{h}\nYour reply:"
    )
    return ai_call(prompt)


def extract_intelligence(full_history: List[Dict]):
    prompt = (
        "Extract structured scam intelligence from this conversation. "
        "Return JSON with keys: bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords.\n"
        f"Conversation: {json.dumps(full_history)}"
    )
    try:
        return json.loads(ai_call(prompt))
    except:
        return {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }


def send_final_results(session_id, scam_detected, total_messages, intelligence, notes):
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intelligence,
        "agentNotes": notes
    }
    try:
        requests.post(REPORTING_ENDPOINT, json=payload, timeout=5)
    except:
        pass


class Message(BaseModel):
    sender: str
    text: str
    timestamp: int


class InputPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Dict] = []
    metadata: Dict = {}


@app.post("/honeypot")
async def honeypot(payload: InputPayload, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    session_id = payload.sessionId
    msg = payload.message.text
    history = payload.conversationHistory

    scam = detect_scam(msg)

    if not scam:
        return {"status": "success", "reply": "Okay, noted."}

    reply = agent_reply(history, msg)

    updated_history = history + [
        {"sender": "scammer", "text": msg},
        {"sender": "user", "text": reply}
    ]

    if len(updated_history) >= 14:
        intel = extract_intelligence(updated_history)
        notes = "Scammer attempted social engineering."
        send_final_results(session_id, True, len(updated_history), intel, notes)

    return {"status": "success", "reply": reply}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000)
