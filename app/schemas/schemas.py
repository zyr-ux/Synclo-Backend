from urllib.parse import urlparse
from typing import List, Optional
from pydantic import BaseModel, EmailStr, field_validator, model_validator
from datetime import datetime
from app.core.config import Settings


class DeviceRegister(BaseModel):
    device_id: str
    device_name: str
    os: Optional[str] = None

class DeviceRename(BaseModel):
    device_name: str

class DeviceOut(BaseModel):
    device_id: str
    device_name: str
    os: Optional[str] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    push_enabled: bool = False

    class Config:
        from_attributes = True

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
        
        # Enforce HTTPS unless running in debug/insecure mode or local address
        if parsed.scheme == "http":
            is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if not (Settings.ALLOW_INSECURE_PUSH_ENDPOINTS or is_local):
                raise ValueError("Push endpoint must use HTTPS in production")
        elif parsed.scheme != "https":
            raise ValueError("Push endpoint must use HTTPS or HTTP (local/dev)")
            
        return v


class ClipboardIn(BaseModel):
    id: str  # Client-generated UUID
    ciphertext: Optional[str] = None # base64 encoded
    nonce: Optional[str] = None # base64 encoded
    blob_version: int = 1
    timestamp: datetime  # Client-generated timestamp (ISO 8601)
    is_deleted: bool = False
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None

class ClipboardOut(BaseModel):
    id: str
    ciphertext: Optional[str] = None # base64 encoded
    nonce: Optional[str] = None # base64 encoded
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
    encrypted_master_key: str  # base64 encoded
    salt: str  # base64 encoded
    kdf_version: int

class UserResponse(BaseModel):
    """Safe user serialization (no hashes/keys)"""
    user_id: str
    email: str
    username: Optional[str] = None
    kdf_version: int
    clipboard_limit: int = 100

    class Config:
        from_attributes = True

class ClipboardLimitUpdate(BaseModel):
    clipboard_limit: int

    @field_validator("clipboard_limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        if v == 0:
            return v
        if not (Settings.MIN_CLIPBOARD_LIMIT <= v <= Settings.MAX_CLIPBOARD_LIMIT):
            raise ValueError(
                f"clipboard_limit must be 0 (infinite) or between {Settings.MIN_CLIPBOARD_LIMIT} and {Settings.MAX_CLIPBOARD_LIMIT}"
            )
        return v

class ClipboardLimitResponse(BaseModel):
    status: str
    clipboard_limit: int
    pruned_count: int


class UserWithE2EE(BaseModel):
    """User with encrypted material (for client-side decryption)"""
    email: str
    username: Optional[str] = None
    encrypted_master_key: str  # base64 encoded
    salt: str  # base64 encoded
    kdf_version: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserLoginWithDevice(BaseModel):
    email: EmailStr
    auth_key: str  # base64 encoded, client-derived HKDF-based authentication key
    device_id: str
    device_name: Optional[str] = None
    os: Optional[str] = None

class UserRegisterWithDevice(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    auth_key: str  # base64 encoded, client-derived HKDF-based authentication key
    device_id: str
    device_name: Optional[str] = "Unnamed Device"
    os: Optional[str] = None
    encrypted_master_key: str  # base64 encoded client-wrapped MK
    salt: str  # base64 encoded KDF salt
    kdf_version: int = 1  # Argon2 parameters version

class SessionInfo(BaseModel):
    device_id: str
    expiry: datetime

class PasswordChange(BaseModel):
    old_auth_key: str  # base64 encoded
    new_auth_key: str  # base64 encoded
    new_encrypted_master_key: str  # base64 encoded, re-wrapped with new password
    new_salt: str  # base64 encoded
    new_kdf_version: int = 1

class SaltResponse(BaseModel):
    salt: str  # base64 encoded
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

