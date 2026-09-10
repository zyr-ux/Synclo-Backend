from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.engine import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False, default=lambda: str(uuid4())
    )
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    auth_key_hash: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_master_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kdf_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    recovery_wrapped_master_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    recovery_key_verifier: Mapped[str] = mapped_column(String, nullable=False)
    session_epoch: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    sync_sequence: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    devices: Mapped[List["Device"]] = relationship("Device", back_populates="owner")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    device_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_id: Mapped[str] = mapped_column(
        String, ForeignKey("users.user_id"), nullable=False, index=True
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=True,
        index=True,
    )

    push_subscription: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    push_subscription_updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    owner: Mapped["User"] = relationship("User", back_populates="devices")

    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_device_user_id_device_id"),)


class Clipboard(Base):
    __tablename__ = "clipboard"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    clipboard_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(
        String, ForeignKey("users.user_id"), nullable=False, index=True
    )
    ciphertext: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    nonce: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    blob_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="0", index=True, nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    is_pinned: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="0", index=True, nullable=False
    )
    pinned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    change_number: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    entry_revision: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    last_device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    owner: Mapped["User"] = relationship("User")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(
        String, ForeignKey("users.user_id"), nullable=False, index=True
    )
    token: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String, nullable=False)

    token_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="0", nullable=False
    )

    user: Mapped["User"] = relationship("User")


class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
