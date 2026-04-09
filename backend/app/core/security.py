import hashlib
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext
from fastapi import Header, HTTPException, Depends
from sqlmodel import Session, select

from .config import settings
from ..db.session import get_session
from ..db.models import APIKey, User

# JWT Configuration
ALGORITHM = "HS256"

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_minutes: int = 60):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_api_key(
    api_key: str = Header(None, alias=settings.API_KEY_HEADER),
    session: Session = Depends(get_session),
) -> APIKey:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API Key")

    h = hashlib.sha256(api_key.encode()).hexdigest()
    statement = select(APIKey).where(APIKey.key_hash == h)
    key_entry = session.exec(statement).first()

    if not key_entry:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    return key_entry

def get_current_user(
    api_key_entry: APIKey = Depends(get_api_key),
    session: Session = Depends(get_session)
) -> User:
    user = session.get(User, api_key_entry.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
