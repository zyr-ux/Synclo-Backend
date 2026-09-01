from urllib.parse import urlparse
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator, model_validator
from datetime import datetime
from app.core.config import Settings
from app.core.constants import LOOPBACK_HOSTS


class DeviceRegister(BaseModel):
    device_id: str
    device_name: str
    os: Optional[str] = None

class DeviceRename(BaseModel):
    device_name: str

class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    device_id: str
    device_name: str
    os: Optional[str] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    push_enabled: bool = False

class PushSubscription(BaseModel):
    push_subscription: str

    @field_validator("push_subscription")
    @classmethod
    def validate_push_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("push_subscription cannot be empty")
        v = v.strip()
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        if parsed.scheme == "http":
            is_local = parsed.hostname in LOOPBACK_HOSTS
            if Settings.HTTPS_ONLY and not is_local:
                raise ValueError("Push endpoint must use HTTPS when HTTPS_ONLY is enabled")
        elif parsed.scheme != "https":
            raise ValueError("Push endpoint must use HTTPS or HTTP")
            
        return v


class ClipboardIn(BaseModel):
    id: str
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None
    blob_version: int = 1
    timestamp: datetime
    is_deleted: bool = False
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None

class ClipboardOut(BaseModel):
    id: str
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None
    blob_version: int
    timestamp: datetime
    updated_at: datetime
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None


class ClipboardPinUpdate(BaseModel):
    is_pinned: bool
    pinned_at: Optional[datetime] = None



class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    username: Optional[str] = None

class TokenWithE2EE(Token):
    encrypted_master_key: str
    salt: str
    kdf_version: int

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: str
    username: Optional[str] = None
    kdf_version: int


class UserWithE2EE(BaseModel):
    email: str
    username: Optional[str] = None
    encrypted_master_key: str
    salt: str
    kdf_version: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserLoginWithDevice(BaseModel):
    email: EmailStr
    auth_key: str
    device_id: str
    device_name: Optional[str] = None
    os: Optional[str] = None

class UserRegisterWithDevice(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    auth_key: str
    device_id: str
    device_name: Optional[str] = "Unnamed Device"
    os: Optional[str] = None
    encrypted_master_key: str
    salt: str
    kdf_version: int = 1

class SessionInfo(BaseModel):
    device_id: str
    expiry: datetime

class PasswordChange(BaseModel):
    old_auth_key: str
    new_auth_key: str
    new_encrypted_master_key: str
    new_salt: str
    new_kdf_version: int = 1

class SaltResponse(BaseModel):
    salt: str
    kdf_version: int

class ClipboardSyncResponse(BaseModel):
    entries: List[ClipboardOut]
    next_offset: int
    has_more: bool
    total_count: int


class UsernameUpdate(BaseModel):
    username: str


class EmailUpdate(BaseModel):
    email: EmailStr


class EmailUpdateResponse(BaseModel):
    message: str
    email: EmailStr
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

