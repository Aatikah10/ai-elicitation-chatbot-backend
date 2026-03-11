from sqlalchemy.orm import Session
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.security import hash_password, verify_password
from datetime import datetime, timedelta, timezone
import os

def create_user(db: Session, name: str, email: str, password: str, role: str = "viewer"):
    hashed = hash_password(password)
    user = User(
        name=name,
        email=email,
        password_hash=hashed,
        role=role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def store_refresh_token(db: Session, user_id, token: str):
    expires_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
    db_token = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token

def revoke_refresh_token(db: Session, token: str):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if db_token:
        db.delete(db_token)
        db.commit()
        return True
    return False

def verify_refresh_token(db: Session, token: str):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if not db_token:
        return None
    
    expires_at = db_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
        
    if expires_at < datetime.now(timezone.utc):
        db.delete(db_token)
        db.commit()
        return None
    return db_token
