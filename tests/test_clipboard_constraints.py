# Test Suite: Database Level Check Constraints on Clipboard Model

from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.database.models import Clipboard, User


def _create_test_user(db_session, email="chk_test@example.com") -> User:
    user = User(
        email=email,
        auth_key_hash="hash",
        encrypted_master_key=b"enc",
        salt=b"salt",
        recovery_wrapped_master_key=b"rec",
        recovery_key_verifier="ver",
    )
    db_session.add(user)
    db_session.flush()
    return user


# 1. Enforce chk_clipboard_deleted_state constraint between is_deleted and deleted_at.
def test_check_constraint_deleted_state_consistency(db_session):
    user = _create_test_user(db_session, email="del_state@example.com")

    clip_invalid_1 = Clipboard(
        clipboard_id="chk_del_1",
        user_id=user.user_id,
        ciphertext=None,
        nonce=None,
        is_deleted=True,
        deleted_at=None,
    )
    db_session.add(clip_invalid_1)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    clip_invalid_2 = Clipboard(
        clipboard_id="chk_del_2",
        user_id=user.user_id,
        ciphertext=b"data",
        nonce=b"nonce",
        is_deleted=False,
        deleted_at=datetime.now(timezone.utc),
    )
    db_session.add(clip_invalid_2)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


# 2. Enforce chk_clipboard_payload_pair constraint between ciphertext and nonce.
def test_check_constraint_payload_pair_consistency(db_session):
    user = _create_test_user(db_session, email="payload_pair@example.com")

    clip_invalid_1 = Clipboard(
        clipboard_id="chk_payload_1",
        user_id=user.user_id,
        ciphertext=b"ciphertext_only",
        nonce=None,
    )
    db_session.add(clip_invalid_1)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    clip_invalid_2 = Clipboard(
        clipboard_id="chk_payload_2",
        user_id=user.user_id,
        ciphertext=None,
        nonce=b"nonce_only",
    )
    db_session.add(clip_invalid_2)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


# 3. Enforce chk_clipboard_deleted_not_pinned constraint preventing deleted pinned items.
def test_check_constraint_deleted_not_pinned(db_session):
    user = _create_test_user(db_session, email="del_pinned@example.com")
    now = datetime.now(timezone.utc)

    clip_invalid = Clipboard(
        clipboard_id="chk_del_pin",
        user_id=user.user_id,
        is_deleted=True,
        deleted_at=now,
        is_pinned=True,
        pinned_at=now,
        ciphertext=None,
        nonce=None,
    )
    db_session.add(clip_invalid)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


# 4. Enforce chk_clipboard_pinned_has_timestamp constraint requiring pinned_at when pinned.
def test_check_constraint_pinned_has_timestamp(db_session):
    user = _create_test_user(db_session, email="pin_ts@example.com")

    clip_invalid = Clipboard(
        clipboard_id="chk_pin_no_ts",
        user_id=user.user_id,
        is_pinned=True,
        pinned_at=None,
        ciphertext=b"data",
        nonce=b"nonce",
    )
    db_session.add(clip_invalid)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()
