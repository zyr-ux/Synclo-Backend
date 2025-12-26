from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class DeviceRegister(BaseModel):
    device_id: str
    device_name: str

class DeviceOut(BaseModel):
    device_id: str
    device_name: str

    class Config:
        from_attributes = True

class ClipboardIn(BaseModel):
    text: str

class ClipboardOut(BaseModel):
    text: str
    timestamp: datetime

class ClipboardOutList(BaseModel):
    history: List[ClipboardOut]

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserLoginWithDevice(UserLogin):
    device_id: str
    device_name: Optional[str] = None

class UserRegisterWithDevice(UserCreate):
    device_id: str
    device_name: Optional[str] = "Unnamed Device"

class SessionInfo(BaseModel):
    device_id: str
    expiry: datetime
