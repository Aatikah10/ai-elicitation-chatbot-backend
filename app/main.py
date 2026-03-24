"""
Main FastAPI application entry point.
"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth_router
from app.core.security import get_current_user, require_role

app = FastAPI(
    title="AI Requirement Elicitation API",
    description="Backend for FYP — AI-powered requirement elicitation chatbot.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────
app.include_router(auth_router.router)

# ── Health ────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "AI Requirement Elicitation API is online"}

# ── Protected (test/demo routes) ──────────────────────────────
@app.get("/protected", tags=["Demo"])
def protected(user: dict = Depends(get_current_user)):
    return {"message": f"Hello {user['user_id']}! You are authenticated."}

@app.get("/admin-only", tags=["Demo"])
def admin_only(user: dict = Depends(require_role("admin"))):
    return {"message": "Welcome, Admin!"}
