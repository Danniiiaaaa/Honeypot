from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
import uvicorn
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ACCESS_TOKEN = os.getenv("API_ACCESS_TOKEN", "")

@app.post("/api/honeypot")
async def honeypot(request: Request):
    data = await request.json()
    token = data.get("api_access_token", "")
    gemini_key = data.get("gemini_key", "")
    user_input = data.get("user_input", "")
    if token != ACCESS_TOKEN:
        return {"reply": "Invalid access token"}
    if not gemini_key:
        return {"reply": "Gemini key missing"}
    if not user_input:
        return {"reply": "Empty prompt"}
    genai.configure(api_key=gemini_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    result = model.generate_content(user_input)
    return {"reply": result.text}

@app.get("/")
async def root():
    return {"message": "Honeypot API running"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
