"""
AISE ASK - The AISE Learning Program Chatbot
Built by: Kevin (contractor)
Date: August 2025 (I think?)
Status: "Works on my machine"

NOTE: If you're reading this, I've already left the company.
      Good luck. The WiFi password is taped under the router.
"""

from config import CORS_ORIGINS, DATABASE_PATH, SECRET_KEY, TOKEN_EXPIRY_SECONDS
from database import init_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import api_gateway
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from config import CORS_ORIGINS

# ============================================================
# Initialize FastAPI app
# ============================================================

app = FastAPI(
    title="AISE ASK",
    description="The AISE Learning Program Chatbot - Ask me anything about the program!",
    version="0.9.3",
)

# ============================================================
# Middleware
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Include routers from api_gateway
# ============================================================

app.include_router(api_gateway.router, prefix="/api")  # uses the router object from api_gateway.py

# ============================================================
# Startup event
# ============================================================

@app.on_event("startup")
async def startup_event():
    """Initialize database and any global state."""
    init_db()
    print("Startup complete: DB initialized")

# ============================================================
# Root endpoint (optional)
# ============================================================

@app.get("/")
async def root():
    return {"message": "AISE ASK is running. Check /docs for API documentation."}
# ============================================================
# STARTUP BANNER
# ============================================================

if __name__ == "__main__":
    import uvicorn

    print("""
    ╔══════════════════════════════════════════════════════╗
    ║                    AISE ASK                         ║
    ║         "It works on my machine" (tm)               ║
    ║                                                     ║
    ║   The monolith lives. The monolith grows.           ║
    ║   The monolith waits for refactoring.               ║
    ║                                                     ║
    ║   Built with mass and minimal planning by Kevin     ║
    ║   Version: 0.9.3-beta-rc2-final-FINAL-v2            ║
    ╚══════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Left reload on in "production" because YOLO
    )
