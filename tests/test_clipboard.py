"""
Test Suite: Clipboard Synchronization, Pin System & Soft Deletions

Scenarios Targeted:
1. Active encrypted clipboard creation and retrieval via latest and ID-specific endpoints.
2. Bulk history deletion preserving pinned items intact.
3. Targeted single item deletion converting entries into tombstones and unsetting pinned status.
4. Custom client-provided 'pinned_at' timestamp preservation and delta delivery.
"""

from tests.conftest import make_clipboard_payload


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
