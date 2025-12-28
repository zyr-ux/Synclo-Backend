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
    ciphertext: str  # base64 encoded
    nonce: str  # base64 encoded
    blob_version: int = 1

class ClipboardOut(BaseModel):
    id: str
    ciphertext: str  # base64 encoded
    nonce: str  # base64 encoded
    blob_version: int
    timestamp: datetime

class ClipboardOutList(BaseModel):
    history: List[ClipboardOut]

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
