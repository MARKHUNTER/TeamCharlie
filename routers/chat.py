import uuid
import sqlite3
import httpx
import jwt
import time
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

# We import our settings from the config file we just made
import config 

# This creates a "sub-section" of our API just for Chat
router = APIRouter(prefix="/chat", tags=["Chat Service"])

# --- DATA MODELS ---
# This defines what the computer expects to see in a Chat request
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

# --- HELPER FUNCTIONS ---

def verify_user(auth_header: str):
    """
    Checks if the user's 'Key' (token) is valid.
    Kevin copy-pasted this 7 times; we just put it here once.
    """
    if not auth_header:
        raise HTTPException(status_code=401, detail="You must be logged in.")
    
    try:
        # Remove 'Bearer ' if it's there
        token = auth_header.replace("Bearer ", "")
        # Decode the token using our secret key
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        
        # Check if the token is too old
        if payload.get("exp") < time.time():
            raise HTTPException(status_code=401, detail="Session expired. Please login again.")
            
        return payload # This contains user_id and username
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid login token.")

# --- THE CHAT ENDPOINT ---

@router.post("/send")
async def send_message(request_data: ChatRequest, authorization: str = Header(None)):
    # 1. Check if the user is who they say they are
    user = verify_user(authorization)
    user_id = user.get("user_id")
    
    # 2. Setup the Session (New chat or continuing one?)
    session_id = request_data.session_id or str(uuid.uuid4())

    # 3. Get the "Memory" (Chat History) from the Database
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT message, response FROM chat_history WHERE user_id = ? AND session_id = ? ORDER BY timestamp DESC LIMIT 10",
        (user_id, session_id)
    )
    rows = cursor.fetchall()
    conn.close()

    # 4. Build the prompt for the AI
    # We start with the 'System' instructions
    messages = [{"role": "system", "content": "You are a helpful AISE assistant."}]
    
    # We add the old messages so the AI remembers the conversation
    for old_msg, old_resp in reversed(rows):
        messages.append({"role": "user", "content": old_msg})
        messages.append({"role": "assistant", "content": old_resp})
    
    # Finally, add the new message from the user
    messages.append({"role": "user", "content": request_data.message})

    # 5. Ask the AI (Groq) for an answer
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.GROQ_API_URL,
                headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
                json={
                    "model": config.GROQ_MODEL,
                    "messages": messages,
                    "temperature": 0.7
                },
                timeout=20.0
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail="The AI is having a bad day. Try again later.")
            
            ai_data = response.json()
            ai_text = ai_data["choices"][0]["message"]["content"]
            tokens = ai_data.get("usage", {}).get("total_tokens", 0)

    except Exception as e:
        print(f"Error calling AI: {e}")
        raise HTTPException(status_code=500, detail="Something went wrong connecting to the AI.")

    # 6. Save the conversation to the Database
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO chat_history (id, user_id, message, response, session_id, tokens_used) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), user_id, request_data.message, ai_text, session_id, tokens)
    )
    conn.commit()
    conn.close()

    # 7. Give the answer back to the user!
    return {
        "answer": ai_text,
        "session_id": session_id
    }