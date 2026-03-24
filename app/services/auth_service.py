"""
Auth service — business logic for user registration, login, and session management.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.security import hash_password, verify_password
from app.core.config import REFRESH_TOKEN_EXPIRE_DAYS


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ── User operations ───────────────────────────────────────────

def create_user(
    db: Session,
    name: str,
    email: str,
    password: str,
    role: str = "viewer",
) -> User:
    user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    if not user.is_active:
        return None
    return user


# ── Refresh token operations ──────────────────────────────────

def store_refresh_token(db: Session, user_id, token: str) -> RefreshToken:
    expires_at = _utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    db_token = RefreshToken(user_id=user_id, token=token, expires_at=expires_at)
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token


def verify_refresh_token(db: Session, token: str) -> Optional[RefreshToken]:
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if not db_token:
        return None
    if _make_aware(db_token.expires_at) < _utc_now():
        db.delete(db_token)
        db.commit()
        return None
    return db_token


def revoke_refresh_token(db: Session, token: str) -> bool:
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if not db_token:
        return False
    db.delete(db_token)
    db.commit()
    return True
