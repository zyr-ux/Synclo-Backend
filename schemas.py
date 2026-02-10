from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

class DeviceRegister(BaseModel):
    device_id: str
    device_name: str

class DeviceOut(BaseModel):
    device_id: str
    device_name: str

    class Config:
        from_attributes = True

class ClipboardIn(BaseModel):
    id: str  # Client-generated UUID
    ciphertext: Optional[str] = None # base64 encoded
    nonce: Optional[str] = None # base64 encoded
    blob_version: int = 1
    timestamp: datetime  # Client-generated timestamp (ISO 8601)
    is_deleted: bool = False

class ClipboardOut(BaseModel):
    id: str
    ciphertext: Optional[str] = None # base64 encoded
    nonce: Optional[str] = None # base64 encoded
    blob_version: int
    timestamp: datetime
    updated_at: datetime
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None



class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenWithE2EE(Token):
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

class UserRegisterWithDevice(BaseModel):
    email: EmailStr
    auth_key: str  # base64 encoded, client-derived HKDF-based authentication key
    device_id: str
    device_name: Optional[str] = "Unnamed Device"
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
