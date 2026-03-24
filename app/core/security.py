"""
Security layer — password hashing, JWT creation/decoding, and FastAPI dependencies.
Fully compatible with python-jose 3.3.0 / passlib 1.7.4 / bcrypt 4.x
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

load_dotenv()

# ── Settings ─────────────────────────────────────────────────
SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# ── Crypto ────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── Token helpers ─────────────────────────────────────────────
def _utc_now() -> datetime:
    """Return current UTC time as an offset-aware datetime."""
    return datetime.now(timezone.utc)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = _utc_now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload["exp"] = expire
    payload["type"] = "access"
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = _utc_now() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    payload["exp"] = expire
    payload["type"] = "refresh"
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependencies ──────────────────────────────────────
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return decode_token(token)


def require_role(role: str):
    """Dependency factory for role-based access control."""
    def checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {role}",
            )
        return current_user
    return checker
