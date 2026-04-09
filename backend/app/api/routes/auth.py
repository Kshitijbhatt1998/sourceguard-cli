import secrets
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from pydantic import BaseModel, EmailStr

from ...db.models import User, APIKey
from ...db.session import get_session
from ...core.security import create_access_token, hash_password, verify_password, get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

class UserSignup(BaseModel):
    email: EmailStr
    password: str
    name: str = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(data: UserSignup, session: Session = Depends(get_session)):
    # Check if user exists
    existing_user = session.exec(select(User).where(User.email == data.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")
    
    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        name=data.name
    )
    session.add(user)
    session.commit()
    return {"message": "User successfully created."}

@router.post("/login")
def login(data: UserLogin, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/api-key", status_code=status.HTTP_201_CREATED)
def create_api_key(
    label: str = "Default CLI Key", 
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    # Generate a fresh key
    raw_key = "sg_" + secrets.token_hex(16)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        label=label
    )
    session.add(api_key)
    session.commit()
    
    return {"api_key": raw_key, "label": label, "msg": "STORE THIS KEY SAFELY. It will not be shown again."}

@router.get("/validate")
def validate(user: User = Depends(get_current_user)):
    return {"status": "valid", "user": user.email}
