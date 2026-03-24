"""
Auth Router — register, login, refresh, logout, and /me endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User
from app.schemas.auth_schema import (
    UserCreate,
    UserLogin,
    Token,
    UserResponse,
    RefreshTokenRequest,
)
from app.services.auth_service import (
    create_user,
    authenticate_user,
    store_refresh_token,
    revoke_refresh_token,
    verify_refresh_token,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Register ──────────────────────────────────────────────────
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db, user_in.name, user_in.email, user_in.password, user_in.role)


# ── Login ─────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user_in.email, user_in.password)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = {"user_id": str(db_user.id), "role": db_user.role}
    access_token = create_access_token(payload)
    refresh_token = create_refresh_token(payload)
    store_refresh_token(db, db_user.id, refresh_token)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# ── Refresh ───────────────────────────────────────────────────
@router.post("/refresh", response_model=Token)
def refresh(req: RefreshTokenRequest, db: Session = Depends(get_db)):
    db_token = verify_refresh_token(db, req.refresh_token)
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate: revoke old, issue new
    revoke_refresh_token(db, req.refresh_token)
    payload = {"user_id": str(user.id), "role": user.role}
    access_token = create_access_token(payload)
    new_refresh = create_refresh_token(payload)
    store_refresh_token(db, user.id, new_refresh)
    return {"access_token": access_token, "refresh_token": new_refresh, "token_type": "bearer"}


# ── Logout ────────────────────────────────────────────────────
@router.post("/logout")
def logout(req: RefreshTokenRequest, db: Session = Depends(get_db)):
    if not revoke_refresh_token(db, req.refresh_token):
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    return {"message": "Successfully logged out"}


# ── Me ────────────────────────────────────────────────────────
@router.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
