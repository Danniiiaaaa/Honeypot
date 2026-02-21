import os
import re
import time
from flask import Flask, request, jsonify
import google.generativeai as genai

app = Flask(__name__)

API_TOKEN = os.getenv("API_ACCESS_TOKEN")
GEMINI_KEY = os.getenv("GEMINI_KEY")

genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

session_data = {}

phone_pattern = re.compile(r"\+?\d[\d\s\-]{7,14}\d")
email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
url_pattern = re.compile(r"https?://[^\s]+")
upi_pattern = re.compile(r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+")
bank_pattern = re.compile(r"\b\d{9,18}\b")

def extract_entities(text):
    phones = phone_pattern.findall(text)
    emails = email_pattern.findall(text)
    urls = url_pattern.findall(text)
    upis = [u for u in upi_pattern.findall(text) if "http" not in u]
    banks = bank_pattern.findall(text)
    return phones, emails, urls, upis, banks

def detect_scam(text):
    scam_words = ["otp", "urgent", "verify", "offer", "blocked", "account", "kyc", "compromised", "refund", "cashback"]
    score = sum(w in text.lower() for w in scam_words)
    return score >= 2

@app.route("/api/honeypot", methods=["POST"])
def honeypot():
    if request.headers.get("x-api-key") != API_TOKEN:
        return jsonify({"error": "invalid access token"}), 401

    data = request.json
    session_id = data.get("sessionId")
    msg = data["message"]["text"]

    if session_id not in session_data:
        session_data[session_id] = {
            "messages": [],
            "start": time.time(),
            "intel": {
                "phoneNumbers": [],
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "emailAddresses": []
            },
            "questions": 0,
            "elicitation": 0,
            "flags": 0,
            "turns": 0,
            "scamDetected": False
        }

    s = session_data[session_id]
    s["turns"] += 1
    s["messages"].append(msg)

    phones, emails, urls, upis, banks = extract_entities(msg)

    s["intel"]["phoneNumbers"] += phones
    s["intel"]["emailAddresses"] += emails
    s["intel"]["phishingLinks"] += urls
    s["intel"]["upiIds"] += upis
    s["intel"]["bankAccounts"] += banks

    if detect_scam(msg):
        s["scamDetected"] = True
        s["flags"] += 1

    prompt = f"""
You are a scam-baiting honeypot. Keep scammers engaged, ask questions, gather details, never give personal info.

Conversation so far:
{s['messages']}

Write only the next message to the scammer.
"""

    ai_reply = model.generate_content(prompt).text.strip()

    if "?" in ai_reply:
        s["questions"] += 1

    if any(k in ai_reply.lower() for k in ["phone", "id", "number", "office", "upi", "link", "email"]):
        s["elicitation"] += 1

    if s["turns"] >= 10 or data.get("endSession"):
        duration = int(time.time() - s["start"])
        final_output = {
            "sessionId": session_id,
            "scamDetected": s["scamDetected"],
            "totalMessagesExchanged": s["turns"],
            "engagementDurationSeconds": duration,
            "extractedIntelligence": s["intel"],
            "agentNotes": "Automated honeypot engagement completed."
        }
        return jsonify({"status": "success", "finalOutput": final_output})

    return jsonify({"status": "success", "reply": ai_reply})

@app.route("/", methods=["GET"])
def health():
    return "Honeypot API Running"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
