from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    LargeBinary,
    DateTime,
    Boolean,
    UniqueConstraint,
    Index,
    CheckConstraint,
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True, nullable=False, default=lambda: str(uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, nullable=True)
    auth_key_hash = Column(String, nullable=False)
    encrypted_master_key = Column(LargeBinary, nullable=False)
    salt = Column(LargeBinary, nullable=False)
    kdf_version = Column(Integer, nullable=False, default=1, server_default="1")
    recovery_wrapped_master_key = Column(LargeBinary, nullable=False)
    recovery_key_verifier = Column(String, nullable=False)
    session_epoch = Column(Integer, default=1, server_default="1", nullable=False)
    sync_sequence = Column(Integer, default=0, server_default="0", nullable=False)

    devices = relationship("Device", back_populates="owner")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    device_name = Column(String, nullable=True)
    os = Column(String, nullable=True)
    user_id = Column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    last_seen = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=True,
        index=True,
    )

    push_subscription = Column(String, nullable=True)
    push_subscription_updated_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="devices")

    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_device_user_id_device_id"),)


class Clipboard(Base):
    __tablename__ = "clipboard"
    id = Column(Integer, primary_key=True, index=True)
    clipboard_id = Column(String, index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    ciphertext = Column(LargeBinary, nullable=True)
    nonce = Column(LargeBinary, nullable=True)
    blob_version = Column(Integer, nullable=False, default=1, server_default="1")
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    is_deleted = Column(Boolean, default=False, server_default="0", index=True, nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    is_pinned = Column(Boolean, default=False, server_default="0", index=True, nullable=False)
    pinned_at = Column(DateTime(timezone=True), nullable=True, index=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    change_number = Column(Integer, default=0, server_default="0", nullable=False)
    entry_revision = Column(Integer, default=1, server_default="1", nullable=False)
    last_device_id = Column(String, nullable=True)

    owner = relationship("User")

    __table_args__ = (
        UniqueConstraint("user_id", "clipboard_id", name="uq_clipboard_user_id_clipboard_id"),
        Index("ix_clipboard_user_change_number", "user_id", "change_number"),
        Index("ix_clipboard_user_deleted_at", "user_id", "is_deleted", "deleted_at"),
        CheckConstraint(
            "(is_deleted = 0 AND deleted_at IS NULL) OR (is_deleted = 1 AND deleted_at IS NOT NULL)",
            name="chk_clipboard_deleted_state",
        ),
        CheckConstraint(
            "(ciphertext IS NULL AND nonce IS NULL) OR (ciphertext IS NOT NULL AND nonce IS NOT NULL)",
            name="chk_clipboard_payload_pair",
        ),
        CheckConstraint(
            "NOT (is_deleted = 1 AND is_pinned = 1)", name="chk_clipboard_deleted_not_pinned"
        ),
        CheckConstraint(
            "NOT (is_pinned = 1 AND pinned_at IS NULL)", name="chk_clipboard_pinned_has_timestamp"
        ),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    expiry = Column(DateTime(timezone=True), index=True, nullable=False)
    device_id = Column(String, nullable=False)

    token_id = Column(String, index=True, nullable=False)
    is_revoked = Column(Boolean, default=False, server_default="0", nullable=False)

    user = relationship("User")


class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    expiry = Column(DateTime(timezone=True), nullable=False, index=True)
