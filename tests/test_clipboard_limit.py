"""
Test Suite: User-Configurable History Quota & Auto-Pruning

Scenarios Targeted:
1. Default clipboard limit initialized on registration and exposed via GET /api/v1/user.
2. Validation rules for clipboard_limit (accepts 0, MIN_CLIPBOARD_LIMIT..MAX_CLIPBOARD_LIMIT, rejects out of range).
3. PATCH and PUT endpoints for /api/v1/user/clipboard-limit.
4. Auto-pruning upon reducing history quota with pinned items immunity.
5. Infinite limit (0) allows unbounded entries without pruning.
6. Auto-pruning triggered upon new clipboard item writes when exceeding limit.
7. WebSocket event broadcast (user_settings_updated and tombstones).
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import patch, AsyncMock
import pytest

from app.core.config import Settings
from app.models.models import Clipboard
from tests.conftest import generate_random_base64


def test_default_clipboard_limit_on_registration_and_profile(client, auth_user):
    # Verify GET /api/v1/user returns clipboard_limit
    res = client.get("/api/v1/user", headers=auth_user["headers"])
    assert res.status_code == 200
    data = res.json()
    assert "clipboard_limit" in data
    assert data["clipboard_limit"] == Settings.DEFAULT_CLIPBOARD_LIMIT


def test_update_clipboard_limit_validation(client, auth_user):
    headers = auth_user["headers"]

    # 1. Setting 0 (infinite) is allowed
    res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 0}, headers=headers)
    assert res.status_code == 200
    assert res.json()["clipboard_limit"] == 0
    assert res.json()["status"] == "success"

    # Verify GET /user reflects 0
    res = client.get("/api/v1/user", headers=headers)
    assert res.json()["clipboard_limit"] == 0

    # 2. Setting MIN_CLIPBOARD_LIMIT (10) is allowed (via PUT)
    res = client.put("/api/v1/user/clipboard-limit", json={"clipboard_limit": 10}, headers=headers)
    assert res.status_code == 200
    assert res.json()["clipboard_limit"] == 10

    # 3. Setting MAX_CLIPBOARD_LIMIT (1000) is allowed
    res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 1000}, headers=headers)
    assert res.status_code == 200
    assert res.json()["clipboard_limit"] == 1000

    # 4. Out of bounds values should fail (422)
    for invalid_val in [-1, -100, 1, 9, 1001, 5000]:
        res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": invalid_val}, headers=headers)
        assert res.status_code == 422, f"Expected 422 for invalid limit {invalid_val}, got {res.status_code}"


def test_update_clipboard_limit_pruning_and_pinned_immunity(client, auth_user, db_session):
    headers = auth_user["headers"]

    # Set quota to 100 first
    client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 100}, headers=headers)

    # Create 15 items with incrementing timestamps
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    item_ids = []
    for i in range(15):
        cid = str(uuid4())
        item_ids.append(cid)
        payload = {
            "id": cid,
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "blob_version": 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "is_pinned": False
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=headers)
        assert res.status_code == 200

    # Pin items at index 1 and 3 (the 2nd and 4th oldest items)
    client.patch(f"/api/v1/clipboard/{item_ids[1]}/pin", json={"is_pinned": True}, headers=headers)
    client.patch(f"/api/v1/clipboard/{item_ids[3]}/pin", json={"is_pinned": True}, headers=headers)

    # Total active items: 15 (2 pinned, 13 non-pinned)
    # Now lower the quota to 10
    patch_res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 10}, headers=headers)
    assert patch_res.status_code == 200
    # 13 non-pinned items with limit=10 -> 3 oldest non-pinned items must be pruned
    assert patch_res.json()["pruned_count"] == 3

    # Check active entries
    all_res = client.get("/api/v1/clipboard/all", headers=headers)
    assert all_res.status_code == 200
    active_items = all_res.json()
    active_ids = {item["id"] for item in active_items}

    # Pinned items MUST still be active
    assert item_ids[1] in active_ids
    assert item_ids[3] in active_ids

    # Total active items should now be 12 (10 non-pinned + 2 pinned)
    assert len(active_items) == 12

    # The 3 oldest non-pinned items (indices 0, 2, 4) should be pruned into tombstones
    pruned_ids = {item_ids[0], item_ids[2], item_ids[4]}
    for pid in pruned_ids:
        assert pid not in active_ids
        tombstone = db_session.query(Clipboard).filter_by(clipboard_id=pid).first()
        assert tombstone.is_deleted is True
        assert tombstone.ciphertext is None
        assert tombstone.nonce is None
        assert tombstone.deleted_at is not None


def test_infinite_limit_zero_prevents_pruning(client, auth_user):
    headers = auth_user["headers"]

    # Set quota to 0 (infinite)
    client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 0}, headers=headers)

    # Add 15 items
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(15):
        payload = {
            "id": str(uuid4()),
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "blob_version": 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "is_pinned": False
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=headers)
        assert res.status_code == 200

    # All 15 should remain active
    all_res = client.get("/api/v1/clipboard/all", headers=headers)
    assert len(all_res.json()) == 15


def test_write_clipboard_triggers_auto_pruning_at_limit(client, auth_user, db_session):
    headers = auth_user["headers"]

    # Set quota to 10
    client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 10}, headers=headers)

    # Insert 10 items
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    item_ids = []
    for i in range(10):
        cid = str(uuid4())
        item_ids.append(cid)
        payload = {
            "id": cid,
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "blob_version": 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "is_pinned": False
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=headers)
        assert res.status_code == 200

    # Verify we currently have 10 items
    all_res = client.get("/api/v1/clipboard/all", headers=headers)
    assert len(all_res.json()) == 10

    # Write the 11th item
    cid_11 = str(uuid4())
    payload_11 = {
        "id": cid_11,
        "ciphertext": generate_random_base64(32),
        "nonce": generate_random_base64(12),
        "blob_version": 1,
        "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
        "is_pinned": False
    }
    res_11 = client.post("/api/v1/clipboard", json=payload_11, headers=headers)
    assert res_11.status_code == 200

    # Oldest item (item_ids[0]) should now be pruned into a tombstone
    all_res = client.get("/api/v1/clipboard/all", headers=headers)
    active_items = all_res.json()
    assert len(active_items) == 10
    active_ids = {item["id"] for item in active_items}
    assert item_ids[0] not in active_ids
    assert cid_11 in active_ids

    oldest_tombstone = db_session.query(Clipboard).filter_by(clipboard_id=item_ids[0]).first()
    assert oldest_tombstone.is_deleted is True
    assert oldest_tombstone.ciphertext is None


@pytest.mark.asyncio
async def test_websocket_user_settings_updated_broadcast(client, auth_user):
    headers = auth_user["headers"]

    with patch("app.endpoints.auth_endpoints.manager.broadcast_to_user", new_callable=AsyncMock) as mock_broadcast:
        res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 50}, headers=headers)
        assert res.status_code == 200

        # Verify broadcast_to_user was called with user_settings_updated
        called_messages = [call.kwargs.get("message") or call.args[1] for call in mock_broadcast.call_args_list]
        settings_events = [m for m in called_messages if m.get("type") == "user_settings_updated"]
        assert len(settings_events) >= 1
        assert settings_events[0]["settings"]["clipboard_limit"] == 50


def test_unauthenticated_clipboard_limit_update(client):
    res = client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 50})
    assert res.status_code == 401


def test_prune_all_users_clipboard_maintenance(client, auth_user, db_session):
    from app.services.utils import prune_all_users_clipboard
    from app.models.models import User

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    headers = auth_user["headers"]
    # Set quota to 10
    client.patch("/api/v1/user/clipboard-limit", json={"clipboard_limit": 10}, headers=headers)

    # Directly insert 12 items into DB bypassing API pruning
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(12):
        entry = Clipboard(
            clipboard_id=str(uuid4()),
            user_id=user_id,
            ciphertext=b"encrypted_content",
            nonce=b"nonce_bytes_12",
            blob_version=1,
            timestamp=base_time + timedelta(minutes=i),
            is_deleted=False,
            is_pinned=False,
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(entry)
    db_session.commit()

    # Run maintenance pruning
    prune_all_users_clipboard(db_session)

    # Check active entries are now pruned to 10
    active_count = (
        db_session.query(Clipboard)
        .filter_by(user_id=user_id, is_deleted=False)
        .count()
    )
    assert active_count == 10

