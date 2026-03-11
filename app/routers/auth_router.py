from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database.db import SessionLocal
from app.schemas.auth_schema import UserCreate, UserLogin, Token, UserResponse, RefreshTokenRequest
from app.services.auth_service import (
    create_user, authenticate_user,
    store_refresh_token, revoke_refresh_token, verify_refresh_token
)
from app.core.security import create_access_token, create_refresh_token, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    from app.models.user import User
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    new_user = create_user(db, user.name, user.email, user.password, user.role)
    return new_user

@router.post("/login", response_model=Token)
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user_in.email, user_in.password)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token({"user_id": str(db_user.id), "role": db_user.role})
    refresh_token = create_refresh_token({"user_id": str(db_user.id), "role": db_user.role})
    
    store_refresh_token(db, db_user.id, refresh_token)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/refresh", response_model=Token)
def refresh(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    db_token = verify_refresh_token(db, request.refresh_token)
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
    from app.models.user import User
    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
        
    access_token = create_access_token({"user_id": str(user.id), "role": user.role})
    new_refresh_token = create_refresh_token({"user_id": str(user.id), "role": user.role})
    
    revoke_refresh_token(db, request.refresh_token)
    store_refresh_token(db, user.id, new_refresh_token)
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@router.post("/logout")
def logout(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    success = revoke_refresh_token(db, request.refresh_token)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.models.user import User
    user_id = current_user.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
