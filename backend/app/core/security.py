import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, Header, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session, select

from .config import settings
from ..db.session import get_session
from ..db.models import APIKey, User

ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_minutes: int = 60) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> str:
    """Decode JWT and return the user_id string stored in 'sub'."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject.")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

def get_api_key(
    api_key: str = Header(None, alias=settings.API_KEY_HEADER),
    session: Session = Depends(get_session),
) -> APIKey:
    """For CLI use — reads the x-api-key header."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key.")
    h = hashlib.sha256(api_key.encode()).hexdigest()
    key_entry = session.exec(select(APIKey).where(APIKey.key_hash == h)).first()
    if not key_entry:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    return key_entry


def get_current_user(
    api_key_entry: APIKey = Depends(get_api_key),
    session: Session = Depends(get_session),
) -> User:
    """CLI auth — resolves User from API key."""
    user = session.get(User, api_key_entry.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


def get_current_user_jwt(
    authorization: str = Header(None),
    session: Session = Depends(get_session),
) -> User:
    """Dashboard auth — resolves User from JWT Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    token = authorization.split(" ", 1)[1]
    user_id = _decode_token(token)
    user = session.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user
