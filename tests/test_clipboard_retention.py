# Test Suite: Server-Side Age-Based Clipboard Retention & Auto-Pruning

from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import patch, AsyncMock
from sqlalchemy import select

from app.core.config import Settings
from app.database.models import Clipboard, User
from app.services.clipboard_service import prune_user_clipboard, prune_all_users_clipboard
from tests.conftest import generate_random_base64


# 1. Soft-delete unpinned clipboard items older than retention limit into tombstones.
def test_age_based_pruning_soft_deletes_expired_items(client, auth_user, db_session):
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=35)
    recent_time = now - timedelta(days=5)

    old_id = str(uuid4())
    old_item = Clipboard(
        clipboard_id=old_id,
        user_id=user_id,
        ciphertext=b"old_cipher",
        nonce=b"old_nonce_12",
        blob_version=1,
        timestamp=old_time,
        updated_at=old_time,
        is_deleted=False,
        is_pinned=False,
    )
    db_session.add(old_item)

    recent_id = str(uuid4())
    recent_item = Clipboard(
        clipboard_id=recent_id,
        user_id=user_id,
        ciphertext=b"recent_cipher",
        nonce=b"recent_nonce",
        blob_version=1,
        timestamp=recent_time,
        updated_at=recent_time,
        is_deleted=False,
        is_pinned=False,
    )
    db_session.add(recent_item)
    db_session.commit()

    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 1
    assert tombstones[0]["id"] == old_id
    assert tombstones[0]["is_deleted"] is True
    assert tombstones[0]["ciphertext"] is None

    db_old = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == old_id)).first()
    assert db_old.is_deleted is True
    assert db_old.ciphertext is None
    assert db_old.deleted_at is not None

    db_recent = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == recent_id)).first()
    assert db_recent.is_deleted is False
    assert db_recent.ciphertext == b"recent_cipher"


# 2. Pinned items remain strictly immune to age-based pruning regardless of age.
def test_pinned_items_immune_to_age_based_pruning(client, auth_user, db_session):
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=90)

    pinned_id = str(uuid4())
    pinned_item = Clipboard(
        clipboard_id=pinned_id,
        user_id=user_id,
        ciphertext=b"pinned_secret",
        nonce=b"pinned_nonce",
        blob_version=1,
        timestamp=old_time,
        updated_at=old_time,
        is_deleted=False,
        is_pinned=True,
        pinned_at=old_time,
    )
    db_session.add(pinned_item)
    db_session.commit()

    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 0

    db_item = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == pinned_id)).first()
    assert db_item.is_deleted is False
    assert db_item.ciphertext == b"pinned_secret"
    assert db_item.is_pinned is True


# 3. Unpinning an old item resets updated_at timestamp granting a fresh retention lifecycle.
def test_unpinning_grants_fresh_lifecycle_grace_period(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    created_time = now - timedelta(days=60)

    cid = str(uuid4())
    item = Clipboard(
        clipboard_id=cid,
        user_id=user_id,
        ciphertext=b"ciphertext_payload",
        nonce=b"nonce_bytes_12",
        blob_version=1,
        timestamp=created_time,
        updated_at=created_time,
        is_deleted=False,
        is_pinned=True,
        pinned_at=created_time,
    )
    db_session.add(item)
    db_session.commit()

    unpin_res = client.patch(
        f"/api/v1/clipboard/{cid}/pin", json={"is_pinned": False}, headers=headers
    )
    assert unpin_res.status_code == 200

    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 0

    active_item = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == cid)).first()
    assert active_item.is_deleted is False
    assert active_item.is_pinned is False


# 4. Updating an existing clipboard item refreshes updated_at and extends retention.
def test_update_clipboard_resets_updated_at_and_extends_retention(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=25)

    cid = str(uuid4())
    item = Clipboard(
        clipboard_id=cid,
        user_id=user_id,
        ciphertext=b"old_data",
        nonce=b"old_nonce_12",
        blob_version=1,
        timestamp=old_time,
        updated_at=old_time,
        is_deleted=False,
        is_pinned=False,
    )
    db_session.add(item)
    db_session.commit()

    new_payload = {
        "id": cid,
        "ciphertext": generate_random_base64(32),
        "nonce": generate_random_base64(12),
        "blob_version": 1,
        "timestamp": now.isoformat(),
        "is_pinned": False,
    }
    update_res = client.post("/api/v1/clipboard", json=new_payload, headers=headers)
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "clipboard updated"

    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 0

    db_item = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == cid)).first()
    assert db_item.is_deleted is False


# 5. Setting retention days to zero disables age-based pruning.
def test_zero_retention_days_disables_pruning(client, auth_user, db_session):
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=100)

    cid = str(uuid4())
    item = Clipboard(
        clipboard_id=cid,
        user_id=user_id,
        ciphertext=b"ancient_data",
        nonce=b"ancient_nonce",
        blob_version=1,
        timestamp=old_time,
        updated_at=old_time,
        is_deleted=False,
        is_pinned=False,
    )
    db_session.add(item)
    db_session.commit()

    tombstones = prune_user_clipboard(user_id, db_session, retention_days=0)
    assert len(tombstones) == 0

    db_item = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == cid)).first()
    assert db_item.is_deleted is False


# 6. REST write endpoint triggers inline pruning and broadcasts tombstone events.
def test_write_clipboard_triggers_age_pruning_and_broadcast(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=Settings.CLIPBOARD_RETENTION_DAYS + 5)
    expired_id = str(uuid4())
    expired_item = Clipboard(
        clipboard_id=expired_id,
        user_id=user_id,
        ciphertext=b"to_be_pruned",
        nonce=b"nonce_bytes_12",
        blob_version=1,
        timestamp=old_time,
        updated_at=old_time,
        is_deleted=False,
        is_pinned=False,
    )
    db_session.add(expired_item)
    db_session.commit()

    new_id = str(uuid4())
    payload = {
        "id": new_id,
        "ciphertext": generate_random_base64(32),
        "nonce": generate_random_base64(12),
        "blob_version": 1,
        "timestamp": now.isoformat(),
        "is_pinned": False,
    }

    with patch(
        "app.endpoints.clipboard_endpoints.manager.broadcast_to_user", new_callable=AsyncMock
    ) as mock_broadcast:
        res = client.post("/api/v1/clipboard", json=payload, headers=headers)
        assert res.status_code == 200

        called_messages = [
            call.kwargs.get("message") or call.args[1] for call in mock_broadcast.call_args_list
        ]
        tombstone_events = [
            m for m in called_messages if m.get("id") == expired_id and m.get("is_deleted") is True
        ]
        assert len(tombstone_events) >= 1

    tombstone = db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == expired_id)).first()
    assert tombstone.is_deleted is True
    assert tombstone.ciphertext is None


# 7. Global multi-user pruning maintenance purges expired entries across all users.
def test_prune_all_users_clipboard_maintenance(client, auth_user, db_session):
    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=40)

    for _ in range(3):
        db_session.add(
            Clipboard(
                clipboard_id=str(uuid4()),
                user_id=user_id,
                ciphertext=b"old_stuff",
                nonce=b"nonce_bytes_12",
                blob_version=1,
                timestamp=old_time,
                updated_at=old_time,
                is_deleted=False,
                is_pinned=False,
            )
        )
    for _ in range(2):
        db_session.add(
            Clipboard(
                clipboard_id=str(uuid4()),
                user_id=user_id,
                ciphertext=b"fresh_stuff",
                nonce=b"nonce_bytes_12",
                blob_version=1,
                timestamp=now,
                updated_at=now,
                is_deleted=False,
                is_pinned=False,
            )
        )
    db_session.commit()

    prune_all_users_clipboard(db_session, retention_days=30)

    active_count = len(
        list(
            db_session.scalars(
                select(Clipboard).where(
                    Clipboard.user_id == user_id, Clipboard.is_deleted.is_(False)
                )
            ).all()
        )
    )
    assert active_count == 2


# 8. Hard deletion cleanup purges expired tombstones while preserving recent tombstones.
def test_cleanup_old_tombstones(auth_user, db_session):
    from app.services.cleanup_service import cleanup_old_tombstones

    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    expired_deleted_at = now - timedelta(days=35)
    recent_deleted_at = now - timedelta(days=5)

    expired_id = str(uuid4())
    db_session.add(
        Clipboard(
            clipboard_id=expired_id,
            user_id=user_id,
            ciphertext=None,
            nonce=None,
            blob_version=1,
            timestamp=expired_deleted_at,
            updated_at=expired_deleted_at,
            is_deleted=True,
            deleted_at=expired_deleted_at,
            is_pinned=False,
        )
    )

    recent_id = str(uuid4())
    db_session.add(
        Clipboard(
            clipboard_id=recent_id,
            user_id=user_id,
            ciphertext=None,
            nonce=None,
            blob_version=1,
            timestamp=recent_deleted_at,
            updated_at=recent_deleted_at,
            is_deleted=True,
            deleted_at=recent_deleted_at,
            is_pinned=False,
        )
    )

    active_id = str(uuid4())
    db_session.add(
        Clipboard(
            clipboard_id=active_id,
            user_id=user_id,
            ciphertext=b"active_data",
            nonce=b"nonce_bytes_12",
            blob_version=1,
            timestamp=now,
            updated_at=now,
            is_deleted=False,
            deleted_at=None,
            is_pinned=False,
        )
    )
    db_session.commit()

    success = cleanup_old_tombstones(db_session)
    assert success is True

    assert db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == expired_id)).first() is None
    assert db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == recent_id)).first() is not None
    assert db_session.scalars(select(Clipboard).where(Clipboard.clipboard_id == active_id)).first() is not None


# 9. Cleanup service purges expired blacklisted access tokens and refresh tokens.
def test_cleanup_expired_tokens(auth_user, db_session):
    from app.database.models import BlacklistedToken, RefreshToken
    from app.services.cleanup_service import (
        cleanup_expired_blacklisted_tokens,
        cleanup_expired_refresh_tokens,
    )

    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(hours=2)
    valid_time = now + timedelta(hours=2)

    db_session.add(BlacklistedToken(token="expired_bl_token", expiry=expired_time))
    db_session.add(BlacklistedToken(token="valid_bl_token", expiry=valid_time))

    db_session.add(
        RefreshToken(
            token="expired_rf_token",
            user_id=user_id,
            device_id="dev_1",
            token_id="tok_1",
            expiry=expired_time,
            is_revoked=False,
        )
    )
    db_session.add(
        RefreshToken(
            token="valid_rf_token",
            user_id=user_id,
            device_id="dev_1",
            token_id="tok_2",
            expiry=valid_time,
            is_revoked=False,
        )
    )
    db_session.commit()

    assert cleanup_expired_blacklisted_tokens(db_session) is True
    assert cleanup_expired_refresh_tokens(db_session) is True

    assert db_session.scalars(select(BlacklistedToken).where(BlacklistedToken.token == "expired_bl_token")).first() is None
    assert db_session.scalars(select(BlacklistedToken).where(BlacklistedToken.token == "valid_bl_token")).first() is not None
    assert db_session.scalars(select(RefreshToken).where(RefreshToken.token == "expired_rf_token")).first() is None
    assert db_session.scalars(select(RefreshToken).where(RefreshToken.token == "valid_rf_token")).first() is not None


# 10. Orchestration helper runs all maintenance routines without unhandled errors.
def test_run_all_cleanup_orchestration(auth_user, db_session):
    from app.services.cleanup_service import run_all_cleanup

    result = run_all_cleanup(db_session)
    assert result.failures == 0
    assert isinstance(result.tombstones, list)
