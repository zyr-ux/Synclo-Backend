from dataclasses import dataclass
from urllib.parse import urlparse
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from datetime import datetime
from app.core.config import Settings
from app.core.constants import (
    LOOPBACK_HOSTS,
    MAX_CIPHERTEXT_LEN,
    MIN_NONCE_LEN,
    MAX_NONCE_LEN,
    ALLOWED_BLOB_VERSIONS,
)
from app.models.models import User


@dataclass(frozen=True)
class AuthContext:
    user: User
    device_id: Optional[str] = None


class DeviceRegister(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=128)
    device_name: str = Field(..., min_length=1, max_length=128)
    os: Optional[str] = Field(None, max_length=32)


class DeviceRename(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=128)


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    device_id: str
    device_name: str
    os: Optional[str] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    push_enabled: bool = False


class PushSubscription(BaseModel):
    push_subscription: str = Field(..., max_length=512)

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
    id: str = Field(..., min_length=1, max_length=128)
    ciphertext: Optional[str] = Field(None, max_length=MAX_CIPHERTEXT_LEN)
    nonce: Optional[str] = Field(None, min_length=MIN_NONCE_LEN, max_length=MAX_NONCE_LEN)
    blob_version: int = Field(1, ge=1, le=100)
    timestamp: datetime
    is_deleted: bool = False
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None

    @field_validator("blob_version")
    @classmethod
    def validate_blob_version(cls, v: int) -> int:
        if v not in ALLOWED_BLOB_VERSIONS:
            raise ValueError(f"Unsupported blob_version: {v}")
        return v

    @field_validator("ciphertext", "nonce")
    @classmethod
    def validate_base64(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        import base64

        try:
            base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("Field must be a valid base64-encoded string")
        return v

    @model_validator(mode="after")
    def validate_payload_pair(self) -> "ClipboardIn":
        if (self.ciphertext is None and self.nonce is not None) or (
            self.ciphertext is not None and self.nonce is None
        ):
            raise ValueError("ciphertext and nonce must either both be present or both be null")
        if not self.is_deleted and self.ciphertext is None:
            raise ValueError("ciphertext cannot be null for active clipboard entries")
        return self


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
    change_number: int
    entry_revision: int
    last_device_id: Optional[str] = None


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
    auth_key: str = Field(..., max_length=512)
    device_id: str = Field(..., min_length=1, max_length=128)
    device_name: Optional[str] = Field(None, max_length=128)
    os: Optional[str] = Field(None, max_length=32)


class UserRegisterWithDevice(BaseModel):
    email: EmailStr
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    auth_key: str = Field(..., max_length=512)
    device_id: str = Field(..., min_length=1, max_length=128)
    device_name: Optional[str] = Field("Unnamed Device", max_length=128)
    os: Optional[str] = Field(None, max_length=32)
    encrypted_master_key: str = Field(..., max_length=2048)
    salt: str = Field(..., max_length=512)
    kdf_version: int = Field(1, ge=1, le=100)
    recovery_wrapped_master_key: str = Field(..., max_length=2048)
    recovery_key_verifier: str = Field(..., max_length=512)


class SessionInfo(BaseModel):
    device_id: str
    expiry: datetime


class PasswordChange(BaseModel):
    old_auth_key: str = Field(..., max_length=512)
    new_auth_key: str = Field(..., max_length=512)
    new_encrypted_master_key: str = Field(..., max_length=2048)
    new_salt: str = Field(..., max_length=512)
    new_kdf_version: int = Field(1, ge=1, le=100)
    new_recovery_wrapped_master_key: Optional[str] = Field(None, max_length=2048)
    new_recovery_key_verifier: Optional[str] = Field(None, max_length=512)


class RecoveryMaterialRequest(BaseModel):
    email: EmailStr


class RecoveryMaterialResponse(BaseModel):
    recovery_wrapped_master_key: str = Field(..., max_length=2048)


class AccountRecoveryRequest(BaseModel):
    email: EmailStr
    recovery_key_verifier: str = Field(..., max_length=512)
    new_auth_key: str = Field(..., max_length=512)
    new_encrypted_master_key: str = Field(..., max_length=2048)
    new_salt: str = Field(..., max_length=512)
    new_kdf_version: int = Field(1, ge=1, le=100)
    new_recovery_wrapped_master_key: str = Field(..., max_length=2048)
    new_recovery_key_verifier: str = Field(..., max_length=512)
    device_id: str = Field(..., min_length=1, max_length=128)
    device_name: Optional[str] = Field("Recovered Device", max_length=128)
    os: Optional[str] = Field(None, max_length=32)


class RecoveryKeyRotateRequest(BaseModel):
    new_recovery_wrapped_master_key: str = Field(..., max_length=2048)
    new_recovery_key_verifier: str = Field(..., max_length=512)


class SaltResponse(BaseModel):
    salt: str
    kdf_version: int


class ClipboardSyncResponse(BaseModel):
    entries: List[ClipboardOut]
    next_cursor: Optional[int] = None
    has_more: bool
    next_offset: Optional[int] = None
    total_count: Optional[int] = None


class UsernameUpdate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)


class EmailUpdate(BaseModel):
    email: EmailStr


class EmailUpdateResponse(BaseModel):
    message: str
    email: EmailStr
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
