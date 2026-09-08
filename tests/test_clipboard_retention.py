"""
Test Suite: Server-Side Age-Based Clipboard Retention & Auto-Pruning

Scenarios Targeted:
1. Expired unpinned items older than CLIPBOARD_RETENTION_DAYS (based on updated_at) are soft-deleted into tombstones.
2. Pinned items are strictly immune to age-based pruning even if months old.
3. Unpinning an old item resets updated_at, granting a fresh 30-day lifecycle (grace period).
4. Setting CLIPBOARD_RETENTION_DAYS=0 disables age-based pruning.
5. REST writes trigger auto-pruning and broadcast deletion tombstones for expired items.
6. Global background cleanup (prune_all_users_clipboard) prunes expired entries across all users.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import patch, AsyncMock

from app.core.config import Settings
from app.models.models import Clipboard, User
from app.utilities.helpers import prune_user_clipboard, prune_all_users_clipboard
from tests.conftest import generate_random_base64


def test_age_based_pruning_soft_deletes_expired_items(client, auth_user, db_session):
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=35)  # 35 days old (> 30 days retention)
    recent_time = now - timedelta(days=5)  # 5 days old (< 30 days retention)

    # Insert an expired unpinned item directly into DB
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

    # Insert a recent unpinned item
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

    # Run pruning with 30-day retention
    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 1
    assert tombstones[0]["id"] == old_id
    assert tombstones[0]["is_deleted"] is True
    assert tombstones[0]["ciphertext"] is None

    # Verify DB state
    db_old = db_session.query(Clipboard).filter_by(clipboard_id=old_id).first()
    assert db_old.is_deleted is True
    assert db_old.ciphertext is None
    assert db_old.deleted_at is not None

    db_recent = db_session.query(Clipboard).filter_by(clipboard_id=recent_id).first()
    assert db_recent.is_deleted is False
    assert db_recent.ciphertext == b"recent_cipher"


def test_pinned_items_immune_to_age_based_pruning(client, auth_user, db_session):
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    # Item is 90 days old, but pinned
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

    db_item = db_session.query(Clipboard).filter_by(clipboard_id=pinned_id).first()
    assert db_item.is_deleted is False
    assert db_item.ciphertext == b"pinned_secret"
    assert db_item.is_pinned is True


def test_unpinning_grants_fresh_lifecycle_grace_period(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    created_time = now - timedelta(days=60)

    # 1. Create a 60-day old pinned item
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

    # 2. Unpin the item via API (which updates updated_at to now)
    unpin_res = client.patch(
        f"/api/v1/clipboard/{cid}/pin", json={"is_pinned": False}, headers=headers
    )
    assert unpin_res.status_code == 200

    # 3. Run pruning with 30-day retention
    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    # Item must NOT be pruned because its updated_at was refreshed to now
    assert len(tombstones) == 0

    active_item = db_session.query(Clipboard).filter_by(clipboard_id=cid).first()
    assert active_item.is_deleted is False
    assert active_item.is_pinned is False


def test_update_clipboard_resets_updated_at_and_extends_retention(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=25)  # 25 days old (approaching 30 days retention limit)

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

    # Update the item via POST /api/v1/clipboard (which resets updated_at to now)
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

    # Run pruning with 30-day retention
    tombstones = prune_user_clipboard(user_id, db_session, retention_days=30)
    assert len(tombstones) == 0

    # Ensure item remains active and not deleted
    db_item = db_session.query(Clipboard).filter_by(clipboard_id=cid).first()
    assert db_item.is_deleted is False


def test_zero_retention_days_disables_pruning(client, auth_user, db_session):
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    # 100-day old unpinned item
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

    # Retention days = 0 (disabled)
    tombstones = prune_user_clipboard(user_id, db_session, retention_days=0)
    assert len(tombstones) == 0

    db_item = db_session.query(Clipboard).filter_by(clipboard_id=cid).first()
    assert db_item.is_deleted is False


def test_write_clipboard_triggers_age_pruning_and_broadcast(client, auth_user, db_session):
    headers = auth_user["headers"]
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    # Insert an expired entry in DB
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

    # Now write a new item via API
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

        # Broadcast should have been called for the tombstone
        called_messages = [
            call.kwargs.get("message") or call.args[1] for call in mock_broadcast.call_args_list
        ]
        tombstone_events = [
            m for m in called_messages if m.get("id") == expired_id and m.get("is_deleted") is True
        ]
        assert len(tombstone_events) >= 1

    # Verify expired item is tombstoned
    tombstone = db_session.query(Clipboard).filter_by(clipboard_id=expired_id).first()
    assert tombstone.is_deleted is True
    assert tombstone.ciphertext is None


def test_prune_all_users_clipboard_maintenance(client, auth_user, db_session):
    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=40)

    # Add 3 old items and 2 fresh items
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

    # Active items should now only be the 2 fresh items
    active_count = db_session.query(Clipboard).filter_by(user_id=user_id, is_deleted=False).count()
    assert active_count == 2


def test_cleanup_old_tombstones(auth_user, db_session):
    from app.utilities.helpers import cleanup_old_tombstones

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    expired_deleted_at = now - timedelta(days=35)
    recent_deleted_at = now - timedelta(days=5)

    # 1. Expired tombstone (deleted 35 days ago, should be hard purged)
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

    # 2. Recent tombstone (deleted 5 days ago, must be preserved)
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

    # 3. Active unpinned item
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

    # Expired tombstone must be permanently deleted
    assert db_session.query(Clipboard).filter_by(clipboard_id=expired_id).first() is None
    # Recent tombstone must remain intact
    assert db_session.query(Clipboard).filter_by(clipboard_id=recent_id).first() is not None
    # Active item must remain intact
    assert db_session.query(Clipboard).filter_by(clipboard_id=active_id).first() is not None


def test_cleanup_expired_tokens(auth_user, db_session):
    from app.models.models import BlacklistedToken, RefreshToken
    from app.utilities.helpers import (
        cleanup_expired_blacklisted_tokens,
        cleanup_expired_refresh_tokens,
    )

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(hours=2)
    valid_time = now + timedelta(hours=2)

    # Blacklisted tokens
    db_session.add(BlacklistedToken(token="expired_bl_token", expiry=expired_time))
    db_session.add(BlacklistedToken(token="valid_bl_token", expiry=valid_time))

    # Refresh tokens
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

    assert db_session.query(BlacklistedToken).filter_by(token="expired_bl_token").first() is None
    assert db_session.query(BlacklistedToken).filter_by(token="valid_bl_token").first() is not None
    assert db_session.query(RefreshToken).filter_by(token="expired_rf_token").first() is None
    assert db_session.query(RefreshToken).filter_by(token="valid_rf_token").first() is not None


def test_run_all_cleanup_orchestration(auth_user, db_session):
    from app.utilities.helpers import run_all_cleanup

    result = run_all_cleanup(db_session)
    assert result.failures == 0
    assert isinstance(result.tombstones, list)
