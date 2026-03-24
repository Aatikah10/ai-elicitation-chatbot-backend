from pydantic import BaseModel, EmailStr, field_validator
import re
from typing import Optional
from datetime import datetime
import uuid

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = "user"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ["admin", "user"]:
            raise ValueError("Role must be either 'admin' or 'user'")
        return v

    @field_validator("name")
    @classmethod
    def name_must_be_alphabetic(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z\s]+$", v):
            raise ValueError("Name must only contain letters and spaces")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
