"""
Test Suite: Clipboard Synchronization, Pin System & Soft Deletions

Scenarios Targeted:
1. Active encrypted clipboard creation and retrieval via latest and ID-specific endpoints.
2. Bulk history deletion preserving pinned items intact.
3. Targeted single item deletion converting entries into tombstones and unsetting pinned status.
4. Custom client-provided 'pinned_at' timestamp preservation and delta delivery.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.schemas import ClipboardIn
from tests.conftest import make_clipboard_payload


def test_clipboard_nonce_respects_declared_minimum_length():
    with pytest.raises(ValidationError):
        ClipboardIn(
            id="clipboard-id",
            ciphertext="aGVsbG8=",
            nonce="MTI=",
            timestamp=datetime.now(timezone.utc),
        )

    entry = ClipboardIn(
        id="clipboard-id",
        ciphertext="aGVsbG8=",
        nonce="MTIzNDU2",
        timestamp=datetime.now(timezone.utc),
    )
    assert entry.nonce == "MTIzNDU2"


def test_create_and_fetch_clipboard_item(client, auth_headers):
    # 1. Create clipboard entry
    clip_id = "clip_test_1"
    payload = make_clipboard_payload(clip_id)
    res = client.post("/api/v1/clipboard", json=payload, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "clipboard synced"

    # 2. Get latest clipboard
    res_latest = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res_latest.status_code == 200
    assert res_latest.json()["id"] == clip_id
    assert res_latest.json()["is_pinned"] is False
    assert res_latest.json()["is_deleted"] is False

    # 3. Get by ID
    res_by_id = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_by_id.status_code == 200
    assert res_by_id.json()["id"] == clip_id


def test_get_latest_clipboard_skips_deleted_tombstones(client, auth_headers):
    # 1. Create an older active item
    client.post("/api/v1/clipboard", json=make_clipboard_payload("item_older", timestamp="2026-08-01T10:00:00Z"), headers=auth_headers)

    # 2. Create a newer item
    client.post("/api/v1/clipboard", json=make_clipboard_payload("item_newer", timestamp="2026-08-01T11:00:00Z"), headers=auth_headers)

    # 3. Delete the newer item
    client.delete("/api/v1/clipboard/item_newer", headers=auth_headers)

    # 4. GET /api/v1/clipboard should return the older active item, skipping the newer deleted tombstone
    res = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["id"] == "item_older"
    assert res.json()["is_deleted"] is False

    # 5. Delete the remaining active item
    client.delete("/api/v1/clipboard/item_older", headers=auth_headers)

    # 6. Now that all items are deleted, GET /api/v1/clipboard should return 404
    res_empty = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res_empty.status_code == 404
    assert res_empty.json()["detail"] == "No clipboard found"


def test_pinned_clipboard_preserved_on_bulk_delete(client, auth_headers):
    # 1. Create regular unpinned item
    client.post("/api/v1/clipboard",
                json=make_clipboard_payload("item_unpinned"), headers=auth_headers)

    # 2. Create pinned item
    client.post("/api/v1/clipboard",
                json=make_clipboard_payload("item_pinned", is_pinned=True), headers=auth_headers)

    # 3. Bulk delete all
    res_del = client.delete("/api/v1/clipboard", headers=auth_headers)
    assert res_del.status_code == 200

    # 4. Check all items - only pinned item should remain active
    res_all = client.get("/api/v1/clipboard/all", headers=auth_headers)
    assert res_all.status_code == 200
    items = res_all.json()
    assert len(items) == 1
    assert items[0]["id"] == "item_pinned"
    assert items[0]["is_pinned"] is True


def test_bulk_delete_broadcasts_tombstones_for_unpinned_items(client, auth_headers, mocker):
    mock_broadcast = mocker.patch("app.endpoints.clipboard_endpoints.manager.broadcast_to_user", new_callable=mocker.AsyncMock)

    # Create 2 unpinned items and 1 pinned item
    client.post("/api/v1/clipboard", json=make_clipboard_payload("unpinned_1"), headers=auth_headers)
    client.post("/api/v1/clipboard", json=make_clipboard_payload("unpinned_2"), headers=auth_headers)
    client.post("/api/v1/clipboard", json=make_clipboard_payload("pinned_1", is_pinned=True), headers=auth_headers)

    mock_broadcast.reset_mock()

    # Bulk delete
    res = client.delete("/api/v1/clipboard", headers=auth_headers)
    assert res.status_code == 200

    # Verify broadcast messages were sent for the 2 unpinned items
    assert mock_broadcast.call_count == 2
    broadcasted_ids = {call.kwargs.get("message", {}).get("id") or (call.args[1].get("id") if len(call.args) > 1 else None) for call in mock_broadcast.call_args_list}
    assert broadcasted_ids == {"unpinned_1", "unpinned_2"}

    for call in mock_broadcast.call_args_list:
        msg = call.kwargs.get("message") or call.args[1]
        assert msg["is_deleted"] is True
        assert msg["is_pinned"] is False
        assert msg["ciphertext"] is None


def test_single_delete_soft_deletes_and_unpins(client, auth_headers):
    client.post("/api/v1/clipboard",
                json=make_clipboard_payload("pinned_to_delete", is_pinned=True), headers=auth_headers)

    # Delete single item directly
    res_del = client.delete("/api/v1/clipboard/pinned_to_delete", headers=auth_headers)
    assert res_del.status_code == 200

    # Item should no longer appear in active list
    res_all = client.get("/api/v1/clipboard/all", headers=auth_headers)
    assert len(res_all.json()) == 0

    # Check with include_deleted=True (tombstone)
    res_tombstone = client.get("/api/v1/clipboard/all?include_deleted=true", headers=auth_headers)
    tombstones = res_tombstone.json()
    assert len(tombstones) == 1
    assert tombstones[0]["id"] == "pinned_to_delete"
    assert tombstones[0]["is_deleted"] is True
    assert tombstones[0]["is_pinned"] is False
    assert tombstones[0]["ciphertext"] is None


def test_pinned_at_timestamp_preservation_and_sync(client, auth_headers):
    # Add pinned item with explicit pinned_at
    custom_pinned_at = "2026-08-20T10:00:00Z"
    clip_id = "pin_ts_custom"
    res = client.post("/api/v1/clipboard", json=make_clipboard_payload(
        clip_id, is_pinned=True, pinned_at=custom_pinned_at, timestamp="2026-08-20T08:00:00Z",
    ), headers=auth_headers)
    assert res.status_code == 200

    # Sync endpoint should return the item with is_pinned=True and matching pinned_at
    res_sync = client.get("/api/v1/clipboard/sync", headers=auth_headers)
    assert res_sync.status_code == 200
    entries = res_sync.json()["entries"]
    match = next(e for e in entries if e["id"] == clip_id)
    assert match["is_pinned"] is True
    assert "2026-08-20T10:00:00" in match["pinned_at"]


def test_pin_and_unpin_clipboard_item(client, auth_headers):
    clip_id = "pin_toggle_test"
    payload = make_clipboard_payload(clip_id, is_pinned=False)
    client.post("/api/v1/clipboard", json=payload, headers=auth_headers)

    # 1. Pin item
    res_pin = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin",
        json={"is_pinned": True},
        headers=auth_headers
    )
    assert res_pin.status_code == 200
    data_pin = res_pin.json()
    assert data_pin["id"] == clip_id
    assert data_pin["is_pinned"] is True
    assert data_pin["pinned_at"] is not None
    assert data_pin["ciphertext"] == payload["ciphertext"]
    assert data_pin["nonce"] == payload["nonce"]

    # 2. Verify via GET
    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["is_pinned"] is True
    assert res_get.json()["pinned_at"] == data_pin["pinned_at"]

    # 3. Unpin item
    res_unpin = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin",
        json={"is_pinned": False},
        headers=auth_headers
    )
    assert res_unpin.status_code == 200
    data_unpin = res_unpin.json()
    assert data_unpin["id"] == clip_id
    assert data_unpin["is_pinned"] is False
    assert data_unpin["pinned_at"] is None

    # 4. Verify via GET
    res_get_unpinned = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get_unpinned.status_code == 200
    assert res_get_unpinned.json()["is_pinned"] is False
    assert res_get_unpinned.json()["pinned_at"] is None


def test_pin_non_existent_item_returns_404(client, auth_headers):
    res = client.patch(
        "/api/v1/clipboard/non_existent_id/pin",
        json={"is_pinned": True},
        headers=auth_headers
    )
    assert res.status_code == 404
    assert res.json()["detail"] == "Clipboard entry not found"


def test_pin_deleted_item_returns_400(client, auth_headers):
    clip_id = "deleted_pin_target"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=auth_headers)
    client.delete(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)

    res = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin",
        json={"is_pinned": True},
        headers=auth_headers
    )
    assert res.status_code == 400
    assert "Cannot pin or unpin a deleted clipboard entry" in res.json()["detail"]


def test_pin_item_user_isolation(client, user_factory):
    user1 = user_factory()
    user2 = user_factory()

    clip_id = "user1_clip_item"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=user1["headers"])

    # User 2 tries to pin User 1's item
    res = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin",
        json={"is_pinned": True},
        headers=user2["headers"]
    )
    assert res.status_code == 404


def test_conflict_stale_write_rejected(client, auth_headers):
    clip_id = "clip_conflict_lww_1"
    # Write at T2
    res1 = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers
    )
    assert res1.status_code == 200

    # Attempt write at older T1
    res2 = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z"),
        headers=auth_headers
    )
    assert res2.status_code == 409
    assert "write rejected" in res2.json()["detail"].lower()


def test_tombstone_cannot_be_resurrected_by_older_write(client, auth_headers):
    clip_id = "clip_resurrect_fail"
    # Delete at T3
    del_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T13:00:00Z")
    del_payload["is_deleted"] = True
    del_payload["ciphertext"] = None
    del_payload["nonce"] = None
    res_del = client.post("/api/v1/clipboard", json=del_payload, headers=auth_headers)
    assert res_del.status_code == 200

    # Attempt write with older T2
    res_write = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers
    )
    assert res_write.status_code == 409
    assert "cannot resurrect" in res_write.json()["detail"].lower()


def test_tombstone_resurrected_by_newer_write(client, auth_headers):
    clip_id = "clip_resurrect_success"
    # Delete at T1
    del_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z")
    del_payload["is_deleted"] = True
    del_payload["ciphertext"] = None
    del_payload["nonce"] = None
    res_del = client.post("/api/v1/clipboard", json=del_payload, headers=auth_headers)
    assert res_del.status_code == 200

    # Resurrect with newer T2
    res_write = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers
    )
    assert res_write.status_code == 200

    # Verify item is active in GET
    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["is_deleted"] is False


def test_equal_timestamp_same_device_collision_rejected(client, auth_user):
    clip_id = "clip_eq_collision"
    ts = "2026-09-04T12:00:00Z"
    p1 = make_clipboard_payload(clip_id, timestamp=ts)
    res1 = client.post("/api/v1/clipboard", json=p1, headers=auth_user["headers"])
    assert res1.status_code == 200

    # Same device writes different payload at identical timestamp
    p2 = make_clipboard_payload(clip_id, timestamp=ts)
    res2 = client.post("/api/v1/clipboard", json=p2, headers=auth_user["headers"])
    assert res2.status_code == 409
    assert "collision" in res2.json()["detail"].lower()


def test_equal_timestamp_different_device_tie_breaker(client, user_factory):
    user = user_factory()
    # Register dev_alpha and dev_beta
    r_alpha = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "dev_alpha",
    })
    token_alpha = r_alpha.json()["access_token"]
    headers_alpha = {"Authorization": f"Bearer {token_alpha}"}

    r_beta = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "dev_beta",
    })
    token_beta = r_beta.json()["access_token"]
    headers_beta = {"Authorization": f"Bearer {token_beta}"}

    clip_id = "clip_tie_breaker"
    ts = "2026-09-04T15:00:00Z"

    # 1. dev_alpha writes at ts
    p1 = make_clipboard_payload(clip_id, timestamp=ts)
    res1 = client.post("/api/v1/clipboard", json=p1, headers=headers_alpha)
    assert res1.status_code == 200

    # 2. dev_beta writes differing payload at identical ts (dev_beta > dev_alpha, wins tie-breaker)
    p2 = make_clipboard_payload(clip_id, timestamp=ts)
    res2 = client.post("/api/v1/clipboard", json=p2, headers=headers_beta)
    assert res2.status_code == 200

    # 3. dev_alpha attempts write at identical ts (dev_alpha < dev_beta, loses tie-breaker)
    p3 = make_clipboard_payload(clip_id, timestamp=ts)
    res3 = client.post("/api/v1/clipboard", json=p3, headers=headers_alpha)
    assert res3.status_code == 409
    assert "tie-breaker lost" in res3.json()["detail"].lower()


def test_clipboard_payload_length_and_version_validation(client, auth_headers):
    import base64
    from app.core.constants import MAX_CIPHERTEXT_LEN, MIN_NONCE_LEN, MAX_NONCE_LEN

    valid_ciphertext = base64.b64encode(b"normal ciphertext payload").decode()
    valid_nonce = base64.b64encode(b"12345678").decode()  # 8 bytes -> 12 base64 chars

    # 1. Nonce too short (< MIN_NONCE_LEN)
    payload_short_nonce = {
        "id": "clip_short_nonce",
        "ciphertext": valid_ciphertext,
        "nonce": "abc",  # 3 chars < 8
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_short_nonce = client.post("/api/v1/clipboard", json=payload_short_nonce, headers=auth_headers)
    assert res_short_nonce.status_code == 422

    # 2. Nonce too long (> MAX_NONCE_LEN)
    payload_long_nonce = {
        "id": "clip_long_nonce",
        "ciphertext": valid_ciphertext,
        "nonce": base64.b64encode(b"A" * (MAX_NONCE_LEN + 10)).decode(),
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_long_nonce = client.post("/api/v1/clipboard", json=payload_long_nonce, headers=auth_headers)
    assert res_long_nonce.status_code == 422

    # 3. Ciphertext too long (> MAX_CIPHERTEXT_LEN)
    payload_long_ct = {
        "id": "clip_long_ct",
        "ciphertext": "A" * (MAX_CIPHERTEXT_LEN + 100),
        "nonce": valid_nonce,
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_long_ct = client.post("/api/v1/clipboard", json=payload_long_ct, headers=auth_headers)
    assert res_long_ct.status_code == 422

    # 4. Unsupported blob_version (not in ALLOWED_BLOB_VERSIONS)
    payload_invalid_blob = {
        "id": "clip_invalid_blob",
        "ciphertext": valid_ciphertext,
        "nonce": valid_nonce,
        "blob_version": 99,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_invalid_blob = client.post("/api/v1/clipboard", json=payload_invalid_blob, headers=auth_headers)
    assert res_invalid_blob.status_code == 422

    # 5. Valid bounds accepted
    payload_valid = {
        "id": "clip_valid_bounds",
        "ciphertext": valid_ciphertext,
        "nonce": valid_nonce,
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_valid = client.post("/api/v1/clipboard", json=payload_valid, headers=auth_headers)
    assert res_valid.status_code == 200


