import os
import time
import json
import random
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Optional
import google.generativeai as genai

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
CURRENT_KEY_INDEX = 0

API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

ai_model = None
app = FastAPI()


def load_model():
    global ai_model, CURRENT_KEY_INDEX
    key = API_KEYS[CURRENT_KEY_INDEX]
    genai.configure(api_key=key)
    ai_model = genai.GenerativeModel("gemini-1.5-flash")


def rotate_key():
    global CURRENT_KEY_INDEX
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    load_model()


load_model()


class Message(BaseModel):
    sender: str
    text: str
    timestamp: int


class InputPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Dict] = []
    metadata: Dict = {}


def ai_call(prompt: str):
    global ai_model
    try:
        return ai_model.generate_content(prompt).text.strip()
    except:
        rotate_key()
        return ai_model.generate_content(prompt).text.strip()


def detect_scam(text: str):
    prompt = f"Is this message a scam? Answer only yes or no. Message: {text}"
    r = ai_call(prompt).lower()
    return "yes" in r


def agent_reply(history: List[Dict], new_msg: str):
    h = ""
    for m in history:
        h += f"{m['sender']}: {m['text']}\n"
    h += f"scammer: {new_msg}\n"

    prompt = (
        "You are a cautious, confused Indian user. Never reveal you are an AI. "
        "Respond naturally to continue the conversation while subtly making the scammer talk more.\n\n"
        f"Conversation:\n{h}\n\nYour reply:"
    )
    return ai_call(prompt)


def extract_intelligence(full_history: List[Dict]):
    prompt = (
        "Extract structured scam intelligence from this conversation. "
        "Return JSON with keys: bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords.\n\n"
        f"Conversation:\n{json.dumps(full_history)}\n"
    )
    try:
        raw = ai_call(prompt)
        return json.loads(raw)
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
        notes = "Scammer attempted social engineering and credential extraction."
        send_final_results(
            session_id=session_id,
            scam_detected=True,
            total_messages=len(updated_history),
            intelligence=intel,
            notes=notes
        )

    return {"status": "success", "reply": reply}
