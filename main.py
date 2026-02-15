from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
import os
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    logger.critical("OPENAI_API_KEY is missing in environment variables!")
    raise RuntimeError("OPENAI_API_KEY not found.")

client = OpenAI(api_key=API_KEY)

class HoneypotRequest(BaseModel):
    prompt: str

@app.post("/api/honeypot")
async def honeypot_endpoint(data: HoneypotRequest):
    user_msg = data.prompt.strip()

    if not user_msg:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    logger.info(f"Incoming prompt: {user_msg}")

    preferred_model = "gpt-4.1-mini"
    fallback_model = "gpt-3.5-turbo"

    try:
        response = client.chat.completions.create(
            model=preferred_model,
            messages=[
                {"role": "system", "content": "You are a honeypot AI. Respond simply."},
                {"role": "user", "content": user_msg}
            ]
        )
        ai_reply = response.choices[0].message.content
        logger.info(f"Reply generated using {preferred_model}")

    except Exception as e:
        logger.error(f"Primary Model Error: {e}")
        logger.info("Fallback to backup model...")
        try:
            response = client.chat.completions.create(
                model=fallback_model,
                messages=[
                    {"role": "system", "content": "You are a honeypot AI. Respond simply."},
                    {"role": "user", "content": user_msg}
                ]
            )
            ai_reply = response.choices[0].message.content
            logger.info(f"Reply generated using {fallback_model}")

        except Exception as e2:
            logger.critical(f"Fallback Model Failed: {e2}")
            raise HTTPException(status_code=500, detail="AI model is not available.")

    return {
        "success": True,
        "model_used": preferred_model,
        "reply": ai_reply
    }

@app.get("/")
async def root():
    return {"status": "Honeypot API running successfully."}
