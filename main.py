import os
import json
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from google.genai import Client
from google.genai.types import GenerateContentConfig

_raw_keys = os.environ.get("GEMINI_KEY", "")
API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
CURRENT_KEY_INDEX = 0

API_ACCESS_TOKEN = os.environ.get("API_ACCESS_TOKEN")
REPORTING_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

client = None

def get_client():
    global client, CURRENT_KEY_INDEX
    key = API_KEYS[CURRENT_KEY_INDEX]
    client = Client(api_key=key)

async def rotate_key():
    global CURRENT_KEY_INDEX
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    get_client()

get_client()
app = FastAPI()

@app.get("/")
async def root():
    return {"status": "running"}

@app.post("/api/honeypot")
async def honeypot(request: Request):
    data = await request.json()
    user_prompt = data.get("prompt", "")

    for _ in range(len(API_KEYS)):
        try:
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=user_prompt,
                config=GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=500
                )
            )
            ai_text = response.text
            return JSONResponse(
                {
                    "status": True,
                    "message": "success",
                    "finalAnswer": ai_text
                }
            )
        except Exception:
            await rotate_key()

    return JSONResponse(
        {
            "status": False,
            "message": "All API keys failed",
            "finalAnswer": ""
        }
    )

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=False)
