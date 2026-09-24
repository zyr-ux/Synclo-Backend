# Test Suite: Data Models & Response Serializers

import base64
from datetime import datetime, timezone
from unittest.mock import patch

from app.database.models import Clipboard, Device, User
from app.database.schemas import ClipboardOut, DeviceOut, UserWithE2EE
from app.services.serializers import (
    clipboard_to_response,
    device_to_response,
    make_tombstone_payload,
    user_to_e2ee_response,
)


# 1. Serialization of User model with raw E2EE keys to base64 response schema.
def test_user_to_e2ee_response_valid():
    raw_mk = b"\x01" * 32
    raw_salt = b"\x02" * 16
    user = User(
        email="alice@synclo.app",
        username="alice",
        encrypted_master_key=raw_mk,
        salt=raw_salt,
        kdf_version=1,
    )

    result = user_to_e2ee_response(user)

    assert isinstance(result, UserWithE2EE)
    assert result.email == "alice@synclo.app"
    assert result.username == "alice"
    assert result.kdf_version == 1
    assert base64.b64decode(result.encrypted_master_key) == raw_mk
    assert base64.b64decode(result.salt) == raw_salt


# 2. Serialization of active encrypted clipboard entry to ClipboardOut schema.
def test_clipboard_to_response_live_entry():
    raw_cipher = b"encrypted_clipboard_bytes"
    raw_nonce = b"12byte_nonce"
    now = datetime(2025, 5, 1, 10, 0, 0, tzinfo=timezone.utc)

    entry = Clipboard(
        clipboard_id="clip-123",
        user_id="user-1",
        ciphertext=raw_cipher,
        nonce=raw_nonce,
        blob_version=1,
        timestamp=now,
        updated_at=now,
        is_deleted=False,
        deleted_at=None,
        is_pinned=True,
        pinned_at=now,
        change_number=42,
        entry_revision=3,
        last_device_id="dev-laptop",
    )

    out = clipboard_to_response(entry)

    assert isinstance(out, ClipboardOut)
    assert out.id == "clip-123"
    assert out.ciphertext is not None
    assert out.nonce is not None
    assert base64.b64decode(out.ciphertext) == raw_cipher
    assert base64.b64decode(out.nonce) == raw_nonce
    assert out.is_deleted is False
    assert out.is_pinned is True
    assert out.change_number == 42
    assert out.entry_revision == 3
    assert out.last_device_id == "dev-laptop"


# 3. Serialization of deleted clipboard tombstone with default fallback fields.
def test_clipboard_to_response_tombstone_defaults():
    now = datetime(2025, 5, 1, 11, 0, 0, tzinfo=timezone.utc)
    entry = Clipboard(
        clipboard_id="clip-tombstone",
        user_id="user-1",
        ciphertext=None,
        nonce=None,
        blob_version=1,
        timestamp=now,
        updated_at=now,
        is_deleted=True,
        deleted_at=now,
        is_pinned=False,
        pinned_at=None,
        change_number=None,
        entry_revision=None,
        last_device_id=None,
    )

    out = clipboard_to_response(entry)

    assert out.ciphertext is None
    assert out.nonce is None
    assert out.is_deleted is True
    assert out.change_number == 0
    assert out.entry_revision == 1
    assert out.is_pinned is False


# 4. Serialization of Device model with presence check and push enablement.
def test_device_to_response_named_and_online():
    now = datetime(2025, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    device = Device(
        device_id="dev-abc",
        user_id="user-xyz",
        device_name="Alice's MacBook",
        os="macOS",
        last_seen=now,
        push_subscription='{"endpoint": "https://push.example.com"}',
    )

    with patch("app.services.serializers.manager.is_device_online", return_value=True) as mock_online:
        out = device_to_response(device)

        mock_online.assert_called_once_with("user-xyz", "dev-abc")
        assert isinstance(out, DeviceOut)
        assert out.device_id == "dev-abc"
        assert out.device_name == "Alice's MacBook"
        assert out.os == "macOS"
        assert out.is_online is True
        assert out.push_enabled is True


# 5. Serialization fallback to 'Unnamed Device' and offline state when fields are None.
def test_device_to_response_fallback_unnamed_and_no_user():
    device = Device(
        device_id="dev-unknown",
        user_id=None,
        device_name=None,
        os="Linux",
        last_seen=None,
        push_subscription=None,
    )

    out = device_to_response(device, user_id=None)

    assert out.device_name == "Unnamed Device"
    assert out.is_online is False
    assert out.push_enabled is False


# 6. Serialization with explicit user_id override for device presence lookup.
def test_device_to_response_override_user_id():
    device = Device(
        device_id="dev-override",
        user_id=None,
        device_name="Workstation",
        os="Windows",
        last_seen=None,
        push_subscription=None,
    )

    with patch("app.services.serializers.manager.is_device_online", return_value=False) as mock_online:
        out = device_to_response(device, user_id="explicit-user-id")
        mock_online.assert_called_once_with("explicit-user-id", "dev-override")
        assert out.is_online is False


# 7. Generation of tombstone wire payload with auto-generated ISO timestamp and defaults.
def test_make_tombstone_payload_auto_timestamp_and_defaults():
    payload = make_tombstone_payload("clip-deleted-1")

    assert payload["type"] == "clipboard_sync"
    assert payload["id"] == "clip-deleted-1"
    assert payload["is_deleted"] is True
    assert payload["is_pinned"] is False
    assert payload["pinned_at"] is None
    assert payload["ciphertext"] is None
    assert payload["nonce"] is None
    assert payload["blob_version"] == 1
    assert isinstance(payload["timestamp"], str)
    assert payload["timestamp"].endswith("Z")

    assert "change_number" not in payload
    assert "entry_revision" not in payload
    assert "last_device_id" not in payload


# 8. Generation of tombstone wire payload with explicit metadata and revision attributes.
def test_make_tombstone_payload_explicit_arguments():
    ts_dt = datetime(2025, 4, 1, 9, 30, 0, tzinfo=timezone.utc)
    payload = make_tombstone_payload(
        clipboard_id="clip-del-2",
        blob_version=2,
        timestamp=ts_dt,
        change_number=105,
        entry_revision=4,
        last_device_id="dev-terminator",
    )

    assert payload["id"] == "clip-del-2"
    assert payload["blob_version"] == 2
    assert payload["timestamp"] == "2025-04-01T09:30:00Z"
    assert payload["change_number"] == 105
    assert payload["entry_revision"] == 4
    assert payload["last_device_id"] == "dev-terminator"


# 9. Generation of tombstone wire payload preserving pre-formatted string timestamps.
def test_make_tombstone_payload_string_timestamp_passthrough():
    custom_ts = "2025-07-07T07:07:07.777Z"
    payload = make_tombstone_payload("clip-del-3", timestamp=custom_ts)
    assert payload["timestamp"] == custom_ts
