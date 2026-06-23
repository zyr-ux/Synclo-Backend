from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary, DateTime, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True, nullable=False, default=lambda: str(uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    auth_key_hash = Column(String, nullable=False)  # bcrypt hash of client-derived auth key
    encrypted_master_key = Column(LargeBinary, nullable=False)
    salt = Column(LargeBinary, nullable=False)
    kdf_version = Column(Integer, nullable=False, default=1)
    devices = relationship("Device", back_populates="owner")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True, nullable=False)
    device_name = Column(String)
    os = Column(String, nullable=True)
    user_id = Column(String, ForeignKey("users.user_id"), index=True)

    owner = relationship("User", back_populates="devices")

class Clipboard(Base):
    __tablename__ = "clipboard"
    id = Column(Integer, primary_key=True, index=True)  # Auto-increment database index
    clipboard_id = Column(String, unique=True, index=True, nullable=False) # UUID business identifier
    user_id = Column(String, ForeignKey("users.user_id"))
    ciphertext = Column(LargeBinary, nullable=True)
    nonce = Column(LargeBinary, nullable=True)
    blob_version = Column(Integer, nullable=False, default=1)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_deleted = Column(Boolean, default=False, index=True)
    deleted_at = Column(DateTime, nullable=True, index=True)
    is_pinned = Column(Boolean, default=False, server_default="0", index=True, nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)

    owner = relationship("User")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.user_id"))
    token = Column(String, unique=True, index=True)
    expiry = Column(DateTime, index=True)
    device_id = Column(String, nullable=False)
    
    # New fields for rotation & reuse detection
    token_id = Column(String, index=True, nullable=False)
    is_revoked = Column(Boolean, default=False)

    user = relationship("User")

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    expiry = Column(DateTime, nullable=False, index=True)


