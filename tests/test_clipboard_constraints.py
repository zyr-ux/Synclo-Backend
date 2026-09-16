"""
Test Suite: Database Level Check Constraints on Clipboard Model

Scenarios Targeted:
1. chk_clipboard_deleted_state:
   (is_deleted = 0 AND deleted_at IS NULL) OR (is_deleted = 1 AND deleted_at IS NOT NULL)
2. chk_clipboard_payload_pair:
   (ciphertext IS NULL AND nonce IS NULL) OR (ciphertext IS NOT NULL AND nonce IS NOT NULL)
3. chk_clipboard_deleted_not_pinned:
   NOT (is_deleted = 1 AND is_pinned = 1)
4. chk_clipboard_pinned_has_timestamp:
   NOT (is_pinned = 1 AND pinned_at IS NULL)
"""

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


def test_check_constraint_deleted_state_consistency(db_session):
    user = _create_test_user(db_session, email="del_state@example.com")

    # Violation 1: is_deleted=True but deleted_at is None
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

    # Violation 2: is_deleted=False but deleted_at is NOT None
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


def test_check_constraint_payload_pair_consistency(db_session):
    user = _create_test_user(db_session, email="payload_pair@example.com")

    # Violation 1: Ciphertext present, nonce None
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

    # Violation 2: Ciphertext None, nonce present
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


def test_check_constraint_deleted_not_pinned(db_session):
    user = _create_test_user(db_session, email="del_pinned@example.com")
    now = datetime.now(timezone.utc)

    # Violation: Both is_deleted=True and is_pinned=True
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


def test_check_constraint_pinned_has_timestamp(db_session):
    user = _create_test_user(db_session, email="pin_ts@example.com")

    # Violation: is_pinned=True but pinned_at is None
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
