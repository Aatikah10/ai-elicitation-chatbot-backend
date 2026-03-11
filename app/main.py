"""
Main FastAPI Application — Entry point for the backend.
"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth_router
from app.core.security import get_current_user, require_role

app = FastAPI(
    title="AI Requirement Chatbot API",
    description="Backend for FYP: AI Requirement Chatbot",
    version="1.0.0"
)

# ── Middlewares ───────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────
app.include_router(auth_router.router)

# ── Health Check / Root ──────────────────────────────────
@app.get("/")
def root():
    return {"message": "AI Requirement Chatbot API is online"}

# ── Example Protected Routes ──────────────────────────────
@app.get("/protected", tags=["Testing"])
def test_protected(user=Depends(get_current_user)):
    return {"message": f"Hello {user['user_id']}, this is a protected route."}

@app.get("/admin-only", tags=["Testing"])
def test_admin(user=Depends(require_role("admin"))):
    return {"message": "Welcome Admin! You have exclusive access."}
