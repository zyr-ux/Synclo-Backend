# Test Suite: Clipboard Synchronization, Pin System & Soft Deletions

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError
from sqlalchemy import select

import app.endpoints.clipboard_endpoints as clip_endpoints
from app.core.constants import MAX_CIPHERTEXT_LEN, MAX_NONCE_LEN
from app.database.engine import run_in_write_transaction
from app.database.models import Clipboard, User
from app.database.schemas import ClipboardIn
from app.services.clipboard_service import _evaluate_lww_conflict
from app.websockets.connection_manager import manager
from tests.conftest import generate_random_base64, make_clipboard_payload


# 1. Nonce minimum length validation respects declared minimum.
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


# 2. Create clipboard entry and fetch via latest and ID-specific endpoints.
def test_create_and_fetch_clipboard_item(client, auth_headers):
    clip_id = "clip_test_1"
    payload = make_clipboard_payload(clip_id)
    res = client.post("/api/v1/clipboard", json=payload, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "clipboard synced"

    res_latest = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res_latest.status_code == 200
    assert res_latest.json()["id"] == clip_id
    assert res_latest.json()["is_pinned"] is False
    assert res_latest.json()["is_deleted"] is False

    res_by_id = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_by_id.status_code == 200
    assert res_by_id.json()["id"] == clip_id


# 3. Latest clipboard skips deleted tombstones and returns 404 when all items are deleted.
def test_get_latest_clipboard_skips_deleted_tombstones(client, auth_headers):
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("item_older", timestamp="2026-08-01T10:00:00Z"),
        headers=auth_headers,
    )
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("item_newer", timestamp="2026-08-01T11:00:00Z"),
        headers=auth_headers,
    )
    client.delete("/api/v1/clipboard/item_newer", headers=auth_headers)

    res = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["id"] == "item_older"
    assert res.json()["is_deleted"] is False

    client.delete("/api/v1/clipboard/item_older", headers=auth_headers)

    res_empty = client.get("/api/v1/clipboard", headers=auth_headers)
    assert res_empty.status_code == 404
    assert res_empty.json()["detail"] == "No clipboard found"


# 4. Bulk deletion marks unpinned items as tombstones while preserving pinned items intact.
def test_pinned_clipboard_preserved_on_bulk_delete(client, auth_headers):
    client.post(
        "/api/v1/clipboard", json=make_clipboard_payload("item_unpinned"), headers=auth_headers
    )
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("item_pinned", is_pinned=True),
        headers=auth_headers,
    )

    res_del = client.delete("/api/v1/clipboard", headers=auth_headers)
    assert res_del.status_code == 200

    res_all = client.get("/api/v1/clipboard/all", headers=auth_headers)
    assert res_all.status_code == 200
    items = res_all.json()
    assert len(items) == 1
    assert items[0]["id"] == "item_pinned"
    assert items[0]["is_pinned"] is True


# 5. Bulk delete broadcasts tombstone messages for unpinned items via connection manager.
def test_bulk_delete_broadcasts_tombstones_for_unpinned_items(client, auth_headers, mocker):
    mock_broadcast = mocker.patch(
        "app.endpoints.clipboard_endpoints.manager.broadcast_to_user", new_callable=mocker.AsyncMock
    )

    client.post(
        "/api/v1/clipboard", json=make_clipboard_payload("unpinned_1"), headers=auth_headers
    )
    client.post(
        "/api/v1/clipboard", json=make_clipboard_payload("unpinned_2"), headers=auth_headers
    )
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("pinned_1", is_pinned=True),
        headers=auth_headers,
    )

    mock_broadcast.reset_mock()

    res = client.delete("/api/v1/clipboard", headers=auth_headers)
    assert res.status_code == 200

    assert mock_broadcast.call_count == 2
    broadcasted_ids = {
        call.kwargs.get("message", {}).get("id")
        or (call.args[1].get("id") if len(call.args) > 1 else None)
        for call in mock_broadcast.call_args_list
    }
    assert broadcasted_ids == {"unpinned_1", "unpinned_2"}

    for call in mock_broadcast.call_args_list:
        msg = call.kwargs.get("message") or call.args[1]
        assert msg["is_deleted"] is True
        assert msg["is_pinned"] is False
        assert msg["ciphertext"] is None


# 6. Single clipboard item deletion converts entry to tombstone and unpins it.
def test_single_delete_soft_deletes_and_unpins(client, auth_headers):
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("pinned_to_delete", is_pinned=True),
        headers=auth_headers,
    )

    res_del = client.delete("/api/v1/clipboard/pinned_to_delete", headers=auth_headers)
    assert res_del.status_code == 200

    res_all = client.get("/api/v1/clipboard/all", headers=auth_headers)
    assert len(res_all.json()) == 0

    res_tombstone = client.get("/api/v1/clipboard/all?include_deleted=true", headers=auth_headers)
    tombstones = res_tombstone.json()
    assert len(tombstones) == 1
    assert tombstones[0]["id"] == "pinned_to_delete"
    assert tombstones[0]["is_deleted"] is True
    assert tombstones[0]["is_pinned"] is False
    assert tombstones[0]["ciphertext"] is None


# 7. Client-provided pinned_at timestamp is preserved and returned in delta sync.
def test_pinned_at_timestamp_preservation_and_sync(client, auth_headers):
    custom_pinned_at = "2026-08-20T10:00:00Z"
    clip_id = "pin_ts_custom"
    res = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(
            clip_id,
            is_pinned=True,
            pinned_at=custom_pinned_at,
            timestamp="2026-08-20T08:00:00Z",
        ),
        headers=auth_headers,
    )
    assert res.status_code == 200

    res_sync = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_sync.status_code == 200
    entries = res_sync.json()["entries"]
    match = next(e for e in entries if e["id"] == clip_id)
    assert match["is_pinned"] is True
    assert "2026-08-20T10:00:00" in match["pinned_at"]


# 8. Pin and unpin clipboard item updates pin state and timestamps.
def test_pin_and_unpin_clipboard_item(client, auth_headers):
    clip_id = "pin_toggle_test"
    payload = make_clipboard_payload(clip_id, is_pinned=False)
    client.post("/api/v1/clipboard", json=payload, headers=auth_headers)

    res_pin = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin", json={"is_pinned": True}, headers=auth_headers
    )
    assert res_pin.status_code == 200
    data_pin = res_pin.json()
    assert data_pin["id"] == clip_id
    assert data_pin["is_pinned"] is True
    assert data_pin["pinned_at"] is not None
    assert data_pin["ciphertext"] == payload["ciphertext"]
    assert data_pin["nonce"] == payload["nonce"]

    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["is_pinned"] is True
    assert res_get.json()["pinned_at"] == data_pin["pinned_at"]

    res_unpin = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin", json={"is_pinned": False}, headers=auth_headers
    )
    assert res_unpin.status_code == 200
    data_unpin = res_unpin.json()
    assert data_unpin["id"] == clip_id
    assert data_unpin["is_pinned"] is False
    assert data_unpin["pinned_at"] is None

    res_get_unpinned = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get_unpinned.status_code == 200
    assert res_get_unpinned.json()["is_pinned"] is False
    assert res_get_unpinned.json()["pinned_at"] is None


# 9. Pinning non-existent clipboard entry returns 404 Not Found.
def test_pin_non_existent_item_returns_404(client, auth_headers):
    res = client.patch(
        "/api/v1/clipboard/non_existent_id/pin", json={"is_pinned": True}, headers=auth_headers
    )
    assert res.status_code == 404
    assert res.json()["detail"] == "Clipboard entry not found"


# 10. Pinning or unpinning deleted clipboard entry returns 400 Bad Request.
def test_pin_deleted_item_returns_400(client, auth_headers):
    clip_id = "deleted_pin_target"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=auth_headers)
    client.delete(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)

    res = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin", json={"is_pinned": True}, headers=auth_headers
    )
    assert res.status_code == 400
    assert "Cannot pin or unpin a deleted clipboard entry" in res.json()["detail"]


# 11. Pinning an item owned by another user returns 404 Not Found.
def test_pin_item_user_isolation(client, user_factory):
    user1 = user_factory()
    user2 = user_factory()

    clip_id = "user1_clip_item"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=user1["headers"])

    res = client.patch(
        f"/api/v1/clipboard/{clip_id}/pin", json={"is_pinned": True}, headers=user2["headers"]
    )
    assert res.status_code == 404


# 12. Clipboard item read and delete enforce strict user isolation.
def test_clipboard_read_and_delete_user_isolation(client, user_factory):
    user1 = user_factory()
    user2 = user_factory()

    clip_id = "user1_private_clip"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=user1["headers"])

    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=user2["headers"])
    assert res_get.status_code == 404

    res_all = client.get("/api/v1/clipboard/all", headers=user2["headers"])
    assert res_all.status_code == 200
    assert len(res_all.json()) == 0

    client.delete(f"/api/v1/clipboard/{clip_id}", headers=user2["headers"])

    res_verify = client.get(f"/api/v1/clipboard/{clip_id}", headers=user1["headers"])
    assert res_verify.status_code == 200
    item1 = res_verify.json()
    assert item1["id"] == clip_id
    assert item1["is_deleted"] is False


# 13. Stale write with older timestamp is rejected with 409 Conflict.
def test_conflict_stale_write_rejected(client, auth_headers):
    clip_id = "clip_conflict_lww_1"
    res1 = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers,
    )
    assert res1.status_code == 200

    res2 = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z"),
        headers=auth_headers,
    )
    assert res2.status_code == 409
    assert "write rejected" in res2.json()["detail"].lower()


# 14. Tombstone cannot be resurrected by a write with older timestamp.
def test_tombstone_cannot_be_resurrected_by_older_write(client, auth_headers):
    clip_id = "clip_resurrect_fail"
    del_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T13:00:00Z")
    del_payload["is_deleted"] = True
    del_payload["ciphertext"] = None
    del_payload["nonce"] = None
    res_del = client.post("/api/v1/clipboard", json=del_payload, headers=auth_headers)
    assert res_del.status_code == 200

    res_write = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers,
    )
    assert res_write.status_code == 409
    assert "cannot resurrect" in res_write.json()["detail"].lower()


# 15. Tombstone can be resurrected by a write with newer timestamp.
def test_tombstone_resurrected_by_newer_write(client, auth_headers):
    clip_id = "clip_resurrect_success"
    del_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z")
    del_payload["is_deleted"] = True
    del_payload["ciphertext"] = None
    del_payload["nonce"] = None
    res_del = client.post("/api/v1/clipboard", json=del_payload, headers=auth_headers)
    assert res_del.status_code == 200

    res_write = client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_headers,
    )
    assert res_write.status_code == 200

    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["is_deleted"] is False


# 16. Equal timestamp write collision from same device is rejected with 409 Conflict.
def test_equal_timestamp_same_device_collision_rejected(client, auth_user):
    clip_id = "clip_eq_collision"
    ts = "2026-09-04T12:00:00Z"
    p1 = make_clipboard_payload(clip_id, timestamp=ts)
    res1 = client.post("/api/v1/clipboard", json=p1, headers=auth_user["headers"])
    assert res1.status_code == 200

    p2 = make_clipboard_payload(clip_id, timestamp=ts)
    res2 = client.post("/api/v1/clipboard", json=p2, headers=auth_user["headers"])
    assert res2.status_code == 409
    assert "collision" in res2.json()["detail"].lower()


# 17. Equal timestamp write from differing device resolves via deterministic device ID tie-breaker.
def test_equal_timestamp_different_device_tie_breaker(client, user_factory):
    user = user_factory()
    r_alpha = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_alpha",
        },
    )
    token_alpha = r_alpha.json()["access_token"]
    headers_alpha = {"Authorization": f"Bearer {token_alpha}"}

    r_beta = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_beta",
        },
    )
    token_beta = r_beta.json()["access_token"]
    headers_beta = {"Authorization": f"Bearer {token_beta}"}

    clip_id = "clip_tie_breaker"
    ts = "2026-09-04T15:00:00Z"

    p1 = make_clipboard_payload(clip_id, timestamp=ts)
    res1 = client.post("/api/v1/clipboard", json=p1, headers=headers_alpha)
    assert res1.status_code == 200

    p2 = make_clipboard_payload(clip_id, timestamp=ts)
    res2 = client.post("/api/v1/clipboard", json=p2, headers=headers_beta)
    assert res2.status_code == 200

    p3 = make_clipboard_payload(clip_id, timestamp=ts)
    res3 = client.post("/api/v1/clipboard", json=p3, headers=headers_alpha)
    assert res3.status_code == 409
    assert "tie-breaker lost" in res3.json()["detail"].lower()


# 18. Clipboard payload field lengths and blob version validations return 422 Unprocessable Entity.
def test_clipboard_payload_length_and_version_validation(client, auth_headers):
    import base64

    valid_ciphertext = base64.b64encode(b"normal ciphertext payload").decode()
    valid_nonce = base64.b64encode(b"12345678").decode()

    payload_short_nonce = {
        "id": "clip_short_nonce",
        "ciphertext": valid_ciphertext,
        "nonce": "abc",
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_short_nonce = client.post(
        "/api/v1/clipboard", json=payload_short_nonce, headers=auth_headers
    )
    assert res_short_nonce.status_code == 422

    payload_long_nonce = {
        "id": "clip_long_nonce",
        "ciphertext": valid_ciphertext,
        "nonce": base64.b64encode(b"A" * (MAX_NONCE_LEN + 10)).decode(),
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_long_nonce = client.post("/api/v1/clipboard", json=payload_long_nonce, headers=auth_headers)
    assert res_long_nonce.status_code == 422

    payload_long_ct = {
        "id": "clip_long_ct",
        "ciphertext": "A" * (MAX_CIPHERTEXT_LEN + 100),
        "nonce": valid_nonce,
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_long_ct = client.post("/api/v1/clipboard", json=payload_long_ct, headers=auth_headers)
    assert res_long_ct.status_code == 422

    payload_invalid_blob = {
        "id": "clip_invalid_blob",
        "ciphertext": valid_ciphertext,
        "nonce": valid_nonce,
        "blob_version": 99,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_invalid_blob = client.post(
        "/api/v1/clipboard", json=payload_invalid_blob, headers=auth_headers
    )
    assert res_invalid_blob.status_code == 422

    payload_valid = {
        "id": "clip_valid_bounds",
        "ciphertext": valid_ciphertext,
        "nonce": valid_nonce,
        "blob_version": 1,
        "timestamp": "2026-09-04T12:00:00Z",
    }
    res_valid = client.post("/api/v1/clipboard", json=payload_valid, headers=auth_headers)
    assert res_valid.status_code == 200


# 19. Duplicate write noop suppresses background push, websocket broadcast, and DB mutation.
def test_duplicate_write_noop_suppresses_broadcast_and_push(
    client, user_factory, monkeypatch, db_session
):
    user = user_factory()
    mock_push = MagicMock()
    monkeypatch.setattr(clip_endpoints, "launch_background_push", mock_push)

    mock_broadcast = AsyncMock()
    monkeypatch.setattr(manager, "broadcast_to_user", mock_broadcast)

    payload = make_clipboard_payload("duplicate_clip_1")

    res1 = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
    assert res1.status_code == 200
    assert mock_push.call_count == 1
    assert mock_broadcast.call_count == 1

    entry_before = db_session.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == "duplicate_clip_1")
    ).first()
    assert entry_before is not None
    rev_before = entry_before.entry_revision
    change_before = entry_before.change_number
    updated_at_before = entry_before.updated_at

    res2 = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
    assert res2.status_code == 200
    assert mock_push.call_count == 1
    assert mock_broadcast.call_count == 1

    db_session.expire_all()
    entry_after = db_session.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == "duplicate_clip_1")
    ).first()
    assert entry_after.entry_revision == rev_before
    assert entry_after.change_number == change_before
    assert entry_after.updated_at == updated_at_before


# 20. Bulk delete on empty clipboard history returns empty message.
def test_bulk_delete_empty_history(client, user_factory):
    user = user_factory()
    res = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert res.status_code == 200
    assert res.json() == {"message": "No clipboard entries to delete."}


# 21. Direct database verification that bulk delete preserves pinned items and tombstones unpinned items.
def test_bulk_delete_preserves_pinned_items(client, user_factory, db_session):
    user = user_factory()
    user_id = db_session.scalars(select(User.user_id).where(User.email == user["email"])).first()

    entry_ids = ["unpinned-1", "unpinned-2", "pinned-1", "pinned-2"]
    for i, cid in enumerate(entry_ids):
        payload = {
            "id": cid,
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "blob_version": 1,
            "is_pinned": i >= 2,
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
        assert res.status_code == 200

    del_res = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert del_res.status_code == 200
    assert del_res.json() == {"message": "2 clipboard entries deleted."}

    stmt = select(Clipboard).where(Clipboard.user_id == user_id)
    records = {c.clipboard_id: c for c in db_session.scalars(stmt).all()}

    assert records["pinned-1"].is_deleted is False
    assert records["pinned-1"].is_pinned is True
    assert records["pinned-1"].ciphertext is not None
    assert records["pinned-1"].nonce is not None

    assert records["pinned-2"].is_deleted is False
    assert records["pinned-2"].is_pinned is True
    assert records["pinned-2"].ciphertext is not None
    assert records["pinned-2"].nonce is not None

    assert records["unpinned-1"].is_deleted is True
    assert records["unpinned-1"].ciphertext is None
    assert records["unpinned-1"].nonce is None

    assert records["unpinned-2"].is_deleted is True
    assert records["unpinned-2"].ciphertext is None
    assert records["unpinned-2"].nonce is None


# 22. Bulk delete assigns contiguous change numbers to created tombstones.
def test_bulk_delete_contiguous_change_numbers(client, user_factory, db_session):
    user = user_factory()
    user_id = db_session.scalars(select(User.user_id).where(User.email == user["email"])).first()

    for i in range(5):
        payload = {
            "id": f"batch-clip-{i}",
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "blob_version": 1,
            "is_pinned": False,
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
        assert res.status_code == 200

    del_res = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert del_res.status_code == 200
    assert del_res.json() == {"message": "5 clipboard entries deleted."}

    stmt = (
        select(Clipboard.change_number)
        .where(Clipboard.user_id == user_id)
        .order_by(Clipboard.change_number.asc())
    )
    all_seqs = list(db_session.scalars(stmt).all())
    tombstone_seqs = all_seqs[-5:]

    assert len(tombstone_seqs) == 5
    for idx in range(len(tombstone_seqs) - 1):
        assert tombstone_seqs[idx + 1] == tombstone_seqs[idx] + 1


# 23. Delta sync allows cold start since_change_number=0 and returns 410 Gone for expired state.
def test_delta_sync_410_when_no_entries_and_sync_sequence_ahead(client, user_factory, db_session):
    user = user_factory()
    user_id = db_session.scalars(select(User.user_id).where(User.email == user["email"])).first()

    def mutate():
        db_user = db_session.scalars(select(User).where(User.user_id == user_id)).first()
        db_user.sync_sequence = 10

    run_in_write_transaction(db_session, mutate)

    res_cold = client.get("/api/v1/clipboard/sync?since_change_number=0", headers=user["headers"])
    assert res_cold.status_code == 200
    assert res_cold.json()["entries"] == []

    res = client.get("/api/v1/clipboard/sync?since_change_number=5", headers=user["headers"])
    assert res.status_code == 410
    assert "Sync state expired" in res.json()["detail"]


# 24. Delta sync pagination limit boundary traversal via cursor.
def test_delta_sync_pagination_limit_boundary(client, user_factory):
    user = user_factory()

    for i in range(3):
        payload = {
            "id": f"page-clip-{i}",
            "ciphertext": generate_random_base64(32),
            "nonce": generate_random_base64(12),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "blob_version": 1,
            "is_pinned": False,
        }
        res = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
        assert res.status_code == 200

    page1 = client.get("/api/v1/clipboard/sync?since_change_number=0&limit=1", headers=user["headers"])
    assert page1.status_code == 200
    p1_data = page1.json()
    assert len(p1_data["entries"]) == 1
    assert p1_data["has_more"] is True
    cursor1 = p1_data["next_cursor"]
    assert cursor1 is not None

    page2 = client.get(f"/api/v1/clipboard/sync?since_change_number={cursor1}&limit=1", headers=user["headers"])
    assert page2.status_code == 200
    p2_data = page2.json()
    assert len(p2_data["entries"]) == 1
    assert p2_data["has_more"] is True
    cursor2 = p2_data["next_cursor"]
    assert cursor2 > cursor1

    page3 = client.get(f"/api/v1/clipboard/sync?since_change_number={cursor2}&limit=1", headers=user["headers"])
    assert page3.status_code == 200
    p3_data = page3.json()
    assert len(p3_data["entries"]) == 1
    assert p3_data["has_more"] is False


def _create_mock_clipboard(
    timestamp: datetime,
    is_deleted: bool = False,
    ciphertext: bytes = b"cipher_a",
    nonce: bytes = b"nonce_a",
    device_id: str = "dev_1",
    is_pinned: bool = False,
) -> Clipboard:
    return Clipboard(
        clipboard_id="test-item-id",
        user_id="user-xyz",
        timestamp=timestamp,
        is_deleted=is_deleted,
        ciphertext=ciphertext if not is_deleted else None,
        nonce=nonce if not is_deleted else None,
        last_device_id=device_id,
        blob_version=1,
        is_pinned=is_pinned,
    )


# 25. LWW conflict engine accepts edit with newer timestamp.
def test_edit_vs_edit_newer_timestamp_accepted():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2025, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(timestamp=t0, device_id="dev_1")

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t1,
        incoming_ciphertext=b"cipher_b",
        incoming_nonce=b"nonce_b",
        incoming_device_id="dev_2",
        is_incoming_tombstone=False,
    )

    assert decision == "accept"
    assert reason == "newer timestamp"


# 26. LWW conflict engine rejects edit with stale timestamp.
def test_edit_vs_edit_stale_timestamp_rejected():
    t0 = datetime(2025, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    t_stale = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(timestamp=t0, device_id="dev_1")

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t_stale,
        incoming_ciphertext=b"cipher_b",
        incoming_nonce=b"nonce_b",
        incoming_device_id="dev_2",
        is_incoming_tombstone=False,
    )

    assert decision == "reject"
    assert reason == "stale timestamp"


# 27. LWW conflict engine treats identical payload and timestamp edit as noop.
def test_edit_vs_edit_identical_payload_and_timestamp_noop():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(
        timestamp=t0,
        ciphertext=b"identical_cipher",
        nonce=b"identical_nonce",
        device_id="dev_1",
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t0,
        incoming_ciphertext=b"identical_cipher",
        incoming_nonce=b"identical_nonce",
        incoming_device_id="dev_2",
        is_incoming_tombstone=False,
    )

    assert decision == "noop"
    assert reason == "identical payload and timestamp"


# 28. LWW conflict engine accepts identical payload with updated pin status.
def test_edit_vs_edit_identical_payload_and_timestamp_with_pin_change_accepted():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(
        timestamp=t0,
        ciphertext=b"identical_cipher",
        nonce=b"identical_nonce",
        device_id="dev_1",
        is_pinned=False,
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t0,
        incoming_ciphertext=b"identical_cipher",
        incoming_nonce=b"identical_nonce",
        incoming_device_id="dev_2",
        is_incoming_tombstone=False,
        incoming_is_pinned=True,
    )

    assert decision == "accept"
    assert reason == "pin status updated"


# 29. LWW conflict engine rejects same-device equal timestamp collision.
def test_edit_vs_edit_same_device_equal_timestamp_collision_rejected():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(
        timestamp=t0,
        ciphertext=b"payload_1",
        nonce=b"nonce_1",
        device_id="dev_fixed",
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t0,
        incoming_ciphertext=b"payload_2",
        incoming_nonce=b"nonce_2",
        incoming_device_id="dev_fixed",
        is_incoming_tombstone=False,
    )

    assert decision == "reject"
    assert reason == "same-device equal timestamp collision"


# 30. LWW conflict engine accepts write when incoming device ID wins tie-breaker.
def test_edit_vs_edit_tiebreaker_won_by_incoming_device():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(
        timestamp=t0,
        ciphertext=b"payload_a",
        nonce=b"nonce_a",
        device_id="device_alpha",
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t0,
        incoming_ciphertext=b"payload_b",
        incoming_nonce=b"nonce_b",
        incoming_device_id="device_beta",
        is_incoming_tombstone=False,
    )

    assert decision == "accept"
    assert reason == "tie-breaker won"


# 31. LWW conflict engine rejects write when incoming device ID loses tie-breaker.
def test_edit_vs_edit_tiebreaker_lost_by_incoming_device():
    t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing = _create_mock_clipboard(
        timestamp=t0,
        ciphertext=b"payload_z",
        nonce=b"nonce_z",
        device_id="device_zebra",
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=t0,
        incoming_ciphertext=b"payload_a",
        incoming_nonce=b"nonce_a",
        incoming_device_id="device_alpha",
        is_incoming_tombstone=False,
    )

    assert decision == "reject"
    assert reason == "tie-breaker lost"


# 32. LWW conflict engine accepts resurrecting tombstone with newer timestamp.
def test_resurrect_tombstone_with_newer_timestamp_accepted():
    t_del = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_new = datetime(2025, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    existing_tombstone = _create_mock_clipboard(timestamp=t_del, is_deleted=True)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_new,
        incoming_ciphertext=b"resurrected_cipher",
        incoming_nonce=b"resurrected_nonce",
        incoming_device_id="dev_new",
        is_incoming_tombstone=False,
    )

    assert decision == "accept"
    assert reason == "resurrection with newer timestamp"


# 33. LWW conflict engine rejects resurrecting tombstone with equal timestamp.
def test_resurrect_tombstone_with_equal_timestamp_rejected():
    t_del = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing_tombstone = _create_mock_clipboard(timestamp=t_del, is_deleted=True)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_del,
        incoming_ciphertext=b"cipher",
        incoming_nonce=b"nonce",
        incoming_device_id="dev_new",
        is_incoming_tombstone=False,
    )

    assert decision == "reject"
    assert reason == "cannot resurrect tombstone with older or equal timestamp"


# 34. LWW conflict engine rejects resurrecting tombstone with older timestamp.
def test_resurrect_tombstone_with_older_timestamp_rejected():
    t_del = datetime(2025, 1, 1, 10, 0, 5, tzinfo=timezone.utc)
    t_old = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing_tombstone = _create_mock_clipboard(timestamp=t_del, is_deleted=True)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_old,
        incoming_ciphertext=b"cipher",
        incoming_nonce=b"nonce",
        incoming_device_id="dev_new",
        is_incoming_tombstone=False,
    )

    assert decision == "reject"
    assert reason == "cannot resurrect tombstone with older or equal timestamp"


# 35. LWW conflict engine accepts tombstone newer than active edit.
def test_tombstone_newer_than_edit_accepted():
    t_edit = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_del = datetime(2025, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    existing_edit = _create_mock_clipboard(timestamp=t_edit, is_deleted=False)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_edit,
        incoming_ts=t_del,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_remover",
        is_incoming_tombstone=True,
    )

    assert decision == "accept"
    assert reason == "tombstone accepted"


# 36. LWW conflict engine accepts tombstone with equal timestamp to active edit.
def test_tombstone_equal_to_edit_accepted():
    t_common = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing_edit = _create_mock_clipboard(timestamp=t_common, is_deleted=False)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_edit,
        incoming_ts=t_common,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_remover",
        is_incoming_tombstone=True,
    )

    assert decision == "accept"
    assert reason == "tombstone accepted"


# 37. LWW conflict engine rejects stale tombstone against newer edit.
def test_tombstone_stale_rejected():
    t_edit = datetime(2025, 1, 1, 10, 0, 5, tzinfo=timezone.utc)
    t_stale_del = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing_edit = _create_mock_clipboard(timestamp=t_edit, is_deleted=False)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_edit,
        incoming_ts=t_stale_del,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_remover",
        is_incoming_tombstone=True,
    )

    assert decision == "reject"
    assert reason == "stale deletion cannot delete newer edit"


# 38. LWW conflict engine accepts newer tombstone over older tombstone.
def test_tombstone_vs_tombstone_newer_accepted():
    t_old_del = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_new_del = datetime(2025, 1, 1, 10, 0, 2, tzinfo=timezone.utc)
    existing_tombstone = _create_mock_clipboard(timestamp=t_old_del, is_deleted=True)

    decision, reason = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_new_del,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_2",
        is_incoming_tombstone=True,
    )

    assert decision == "accept"
    assert reason == "newer tombstone"


# 39. LWW conflict engine treats equal or older tombstone over existing tombstone as noop.
def test_tombstone_vs_tombstone_equal_or_older_noop():
    t_del = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    existing_tombstone = _create_mock_clipboard(timestamp=t_del, is_deleted=True)

    dec1, reason1 = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_del,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_2",
        is_incoming_tombstone=True,
    )
    assert dec1 == "noop"
    assert reason1 == "existing tombstone preserved"

    t_older = datetime(2025, 1, 1, 9, 59, 59, tzinfo=timezone.utc)
    dec2, reason2 = _evaluate_lww_conflict(
        existing=existing_tombstone,
        incoming_ts=t_older,
        incoming_ciphertext=None,
        incoming_nonce=None,
        incoming_device_id="dev_2",
        is_incoming_tombstone=True,
    )
    assert dec2 == "noop"
    assert reason2 == "existing tombstone preserved"


# 40. LWW conflict engine handles timezone offsets accurately when comparing timestamps.
def test_lww_handles_naive_and_offset_timezones_accurately():
    utc_t0 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    ist_t0 = datetime(2025, 1, 1, 15, 30, 0, tzinfo=ist_tz)

    existing = _create_mock_clipboard(
        timestamp=utc_t0,
        ciphertext=b"same_payload",
        nonce=b"same_nonce",
        device_id="dev_a",
    )

    decision, reason = _evaluate_lww_conflict(
        existing=existing,
        incoming_ts=ist_t0,
        incoming_ciphertext=b"same_payload",
        incoming_nonce=b"same_nonce",
        incoming_device_id="dev_b",
        is_incoming_tombstone=False,
    )

    assert decision == "noop"
    assert reason == "identical payload and timestamp"


# 41. Bulk delete history broadcasts tombstones to connected websocket clients.
def test_bulk_delete_history_broadcasts_tombstones_via_websocket(client, user_factory, mocker):
    mocker.patch("app.endpoints.clipboard_endpoints.launch_background_push")
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_bulk_ws_2",
        },
    )
    assert dev2_res.status_code == 200
    token_dev2 = dev2_res.json()["access_token"]

    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("unpinned_bulk_1"),
        headers=user["headers"],
    )
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("unpinned_bulk_2"),
        headers=user["headers"],
    )
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("pinned_bulk_1", is_pinned=True),
        headers=user["headers"],
    )

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws2:
        res = client.delete("/api/v1/clipboard", headers=user["headers"])
        assert res.status_code == 200
        assert res.json() == {"message": "2 clipboard entries deleted."}

        received = []
        for _ in range(20):
            msg = ws2.receive_json()
            if msg.get("type") == "ping":
                ws2.send_json({"type": "pong"})
                continue
            received.append(msg)
            if len(received) == 2:
                break

        assert len(received) == 2
        received_ids = {m["id"] for m in received}
        assert received_ids == {"unpinned_bulk_1", "unpinned_bulk_2"}
        for m in received:
            assert m["type"] == "clipboard_sync"
            assert m["is_deleted"] is True
            assert m["is_pinned"] is False
            assert m["ciphertext"] is None


# 42. Bulk delete history triggers background push dispatch excluding initiator device.
def test_bulk_delete_history_triggers_push_dispatch(client, user_factory, mocker):
    mock_push = mocker.patch("app.endpoints.clipboard_endpoints.launch_background_push")
    user = user_factory()
    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("push_bulk_1"),
        headers=user["headers"],
    )
    mock_push.reset_mock()

    res = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert res.status_code == 200

    profile = client.get("/api/v1/user", headers=user["headers"]).json()
    user_id = profile["user_id"]
    mock_push.assert_called_once_with(user_id=user_id, exclude_device=user["device_id"])


# 43. Bulk delete returns no entries message when all items are already pinned or absent.
def test_bulk_delete_history_empty_returns_no_entries_message(client, user_factory):
    user = user_factory()
    res = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert res.status_code == 200
    assert res.json() == {"message": "No clipboard entries to delete."}

    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload("pinned_only_item", is_pinned=True),
        headers=user["headers"],
    )
    res_pinned = client.delete("/api/v1/clipboard", headers=user["headers"])
    assert res_pinned.status_code == 200
    assert res_pinned.json() == {"message": "No clipboard entries to delete."}


# 44. Upserting identical payload with pin status toggle updates the entry and increments change sequence.
def test_upsert_identical_payload_and_timestamp_with_pin_change_updates_entry(
    client, user_factory
):
    user = user_factory()
    payload = make_clipboard_payload("pin_toggle_test", is_pinned=False)

    res1 = client.post("/api/v1/clipboard", json=payload, headers=user["headers"])
    assert res1.status_code == 200

    entry1 = client.get(f"/api/v1/clipboard/{payload['id']}", headers=user["headers"]).json()
    assert entry1["is_pinned"] is False
    seq1 = entry1["change_number"]

    payload_pinned = dict(payload)
    payload_pinned["is_pinned"] = True
    res2 = client.post("/api/v1/clipboard", json=payload_pinned, headers=user["headers"])
    assert res2.status_code == 200

    entry2 = client.get(f"/api/v1/clipboard/{payload['id']}", headers=user["headers"]).json()
    assert entry2["is_pinned"] is True
    assert entry2["change_number"] > seq1
