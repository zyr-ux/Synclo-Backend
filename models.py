from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary, DateTime, Boolean
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    devices = relationship("Device", back_populates="owner")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True)
    device_name = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)

    owner = relationship("User", back_populates="devices")

class EncryptionKey(Base):
    __tablename__ = "encryption_keys"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    key = Column(LargeBinary, nullable=False)

    owner = relationship("User")

class Clipboard(Base):
    __tablename__ = "clipboard"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True, nullable=False) # New UUID column
    user_id = Column(Integer, ForeignKey("users.id"))
    encrypted_data = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True, index=True)
    expiry = Column(DateTime, index=True)
    device_id = Column(String, nullable=False)
    
    # New fields for rotation & reuse detection
    family_id = Column(String, index=True, nullable=False)
    is_revoked = Column(Boolean, default=False)

    user = relationship("User")

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    expiry = Column(DateTime, nullable=False, index=True)


