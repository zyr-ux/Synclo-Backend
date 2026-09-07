"""
Test Suite: Offline Delta Synchronization, Tombstones & Pagination

Scenarios Targeted:
1. Incremental delta sync returning only new/updated entries and deleted tombstones after client's last sync time.
2. Offset and limit based batch pagination across multiple sync items ('limit', 'offset', 'next_offset', 'has_more').
3. Expired sync state rejection returning 410 Gone when 'since' exceeds 30-day tombstone retention period.
"""

import datetime
from tests.conftest import make_clipboard_payload


def test_delta_sync_flow_and_tombstones(client, auth_headers, clip_payload, now_iso):
    # 1. Initial sync before any items -> empty
    res_initial = client.get("/api/v1/clipboard/sync", headers=auth_headers)
    assert res_initial.status_code == 200
    assert len(res_initial.json()["entries"]) == 0

    # Capture a baseline timestamp from the response Date header,
    # falling back to current UTC time if the header isn't present.
    from email.utils import parsedate_to_datetime
    date_header = res_initial.headers.get("date")
    if date_header:
        t0 = parsedate_to_datetime(date_header).isoformat().replace("+00:00", "Z")
    else:
        t0 = now_iso()

    # 2. Add Item A
    item_a_id = "sync_item_a"
    res_a = client.post("/api/v1/clipboard",
                        json=clip_payload(item_a_id), headers=auth_headers)
    assert res_a.status_code == 200

    # 3. Sync since t0 -> returns Item A
    res_sync1 = client.get("/api/v1/clipboard/sync", params={"since": t0}, headers=auth_headers)
    assert res_sync1.status_code == 200
    sync_data1 = res_sync1.json()
    assert len(sync_data1["entries"]) == 1
    assert sync_data1["entries"][0]["id"] == item_a_id
    # Use server's updated_at as cursor for next delta
    t1 = sync_data1["entries"][0]["updated_at"]

    # 4. Add Item B
    item_b_id = "sync_item_b"
    client.post("/api/v1/clipboard",
                json=clip_payload(item_b_id), headers=auth_headers)

    # 5. Sync since t1 -> returns only Item B
    res_sync2 = client.get("/api/v1/clipboard/sync", params={"since": t1}, headers=auth_headers)
    assert res_sync2.status_code == 200
    sync_data2 = res_sync2.json()
    assert len(sync_data2["entries"]) == 1
    assert sync_data2["entries"][0]["id"] == item_b_id

    # 6. Delete Item A (creating tombstone)
    client.delete(f"/api/v1/clipboard/{item_a_id}", headers=auth_headers)

    # 7. Sync since t0 -> returns tombstone for A and active B
    res_sync_all = client.get("/api/v1/clipboard/sync", params={"since": t0}, headers=auth_headers)
    assert res_sync_all.status_code == 200
    all_entries = {e["id"]: e for e in res_sync_all.json()["entries"]}
    assert len(all_entries) == 2
    assert all_entries[item_a_id]["is_deleted"] is True
    assert all_entries[item_a_id]["ciphertext"] is None
    assert all_entries[item_b_id]["is_deleted"] is False


def test_delta_sync_pagination(client, auth_headers):
    # Insert 5 items
    for i in range(5):
        client.post(
            "/api/v1/clipboard",
            json=make_clipboard_payload(f"page_item_{i}"),
            headers=auth_headers,
        )

    # Fetch page 1 (limit 2, offset 0) -> sorted by updated_at ASC
    page1 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": 0}, headers=auth_headers).json()
    assert [e["id"] for e in page1["entries"]] == ["page_item_0", "page_item_1"]
    assert page1["total_count"] == 5
    assert page1["next_offset"] == 2
    assert page1["has_more"] is True

    # Fetch page 2 (limit 2, offset 2)
    page2 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": page1["next_offset"]}, headers=auth_headers).json()
    assert [e["id"] for e in page2["entries"]] == ["page_item_2", "page_item_3"]
    assert page2["total_count"] == 5
    assert page2["next_offset"] == 4
    assert page2["has_more"] is True

    # Fetch page 3 (limit 2, offset 4) -> 1 remaining
    page3 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": page2["next_offset"]}, headers=auth_headers).json()
    assert [e["id"] for e in page3["entries"]] == ["page_item_4"]
    assert page3["total_count"] == 5
    assert page3["next_offset"] == 5
    assert page3["has_more"] is False


def test_expired_sync_state_returns_410(client, auth_headers):
    old_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)).isoformat().replace("+00:00", "Z")
    res = client.get("/api/v1/clipboard/sync", params={"since": old_time}, headers=auth_headers)
    assert res.status_code == 410


def test_delta_sync_boundary_condition_410(client, auth_headers):
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # 29.9 days ago (within 30 days retention cutoff) -> should succeed (200 OK)
    valid_time = (now - datetime.timedelta(days=29, hours=20)).isoformat().replace("+00:00", "Z")
    res_valid = client.get("/api/v1/clipboard/sync", params={"since": valid_time}, headers=auth_headers)
    assert res_valid.status_code == 200

    # 30.1 days ago (exceeds 30 days retention cutoff) -> should return 410 Gone
    expired_time = (now - datetime.timedelta(days=30, hours=2)).isoformat().replace("+00:00", "Z")
    res_expired = client.get("/api/v1/clipboard/sync", params={"since": expired_time}, headers=auth_headers)
    assert res_expired.status_code == 410


def test_delta_sync_keyset_cursor_pagination(client, auth_headers, clip_payload):
    # Create 4 items
    for i in range(4):
        client.post("/api/v1/clipboard", json=clip_payload(f"cursor_item_{i}"), headers=auth_headers)

    # Page 1: since_change_number=0, limit=2
    r1 = client.get("/api/v1/clipboard/sync", params={"since_change_number": 0, "limit": 2}, headers=auth_headers)
    assert r1.status_code == 200
    p1 = r1.json()
    assert [e["id"] for e in p1["entries"]] == ["cursor_item_0", "cursor_item_1"]
    assert p1["has_more"] is True
    assert p1["next_cursor"] is not None
    cursor1 = p1["next_cursor"]

    # Page 2: using cursor1
    r2 = client.get("/api/v1/clipboard/sync", params={"since_change_number": cursor1, "limit": 2}, headers=auth_headers)
    assert r2.status_code == 200
    p2 = r2.json()
    assert [e["id"] for e in p2["entries"]] == ["cursor_item_2", "cursor_item_3"]
    cursor2 = p2["next_cursor"]

    # Page 3: using cursor2 -> no more items
    r3 = client.get("/api/v1/clipboard/sync", params={"since_change_number": cursor2, "limit": 2}, headers=auth_headers)
    assert r3.status_code == 200
    p3 = r3.json()
    assert len(p3["entries"]) == 0
    assert p3["has_more"] is False
    assert p3["next_cursor"] is None


def test_pin_increments_sync_sequence(client, auth_headers, clip_payload):
    # 1. Create item
    res_create = client.post("/api/v1/clipboard", json=clip_payload("seq_pin_item"), headers=auth_headers)
    assert res_create.status_code == 200

    r_sync1 = client.get("/api/v1/clipboard/sync", params={"since_change_number": 0, "limit": 10}, headers=auth_headers)
    entries1 = r_sync1.json()["entries"]
    assert len(entries1) >= 1
    seq_before = entries1[-1]["change_number"]

    # 2. Pin item
    res_pin = client.patch("/api/v1/clipboard/seq_pin_item/pin", json={"is_pinned": True}, headers=auth_headers)
    assert res_pin.status_code == 200
    assert res_pin.json()["change_number"] > seq_before

    # 3. Sync since seq_before -> should return the pin update!
    r_sync2 = client.get("/api/v1/clipboard/sync", params={"since_change_number": seq_before, "limit": 10}, headers=auth_headers)
    entries2 = r_sync2.json()["entries"]
    assert len(entries2) == 1
    assert entries2[0]["id"] == "seq_pin_item"
    assert entries2[0]["is_pinned"] is True


def test_delta_sync_keyset_sequence_410_retention_cutoff(client, auth_headers, clip_payload, db_session):
    from app.models.models import Clipboard, User

    # 1. Create 3 items
    for i in range(1, 4):
        client.post("/api/v1/clipboard", json=clip_payload(f"seq_410_item_{i}"), headers=auth_headers)

    from app.core.database import run_in_write_transaction

    # 2. Hard-purge item 1 and item 2 to simulate expired tombstones cleaned up after 30 days
    def purge():
        db_session.query(Clipboard).filter(
            Clipboard.clipboard_id.in_(["seq_410_item_1", "seq_410_item_2"])
        ).delete(synchronize_session="fetch")

    run_in_write_transaction(db_session, purge)
    db_session.expire_all()

    # Client requesting since_change_number=1 (behind oldest_entry.change_number - 1) gets 410 Gone
    res_expired = client.get("/api/v1/clipboard/sync", params={"since_change_number": 1}, headers=auth_headers)
    assert res_expired.status_code == 410
    assert "Sync state expired" in res_expired.json()["detail"]

    # Client requesting since_change_number=2 (at oldest_entry.change_number - 1) succeeds
    res_valid = client.get("/api/v1/clipboard/sync", params={"since_change_number": 2}, headers=auth_headers)
    assert res_valid.status_code == 200
    assert len(res_valid.json()["entries"]) == 1
    assert res_valid.json()["entries"][0]["id"] == "seq_410_item_3"


def test_delta_sync_keyset_sequence_410_when_entries_older_than_retention(client, auth_headers, clip_payload, db_session):
    from app.models.models import Clipboard

    # Create 2 items
    client.post("/api/v1/clipboard", json=clip_payload("seq_old_1"), headers=auth_headers)
    client.post("/api/v1/clipboard", json=clip_payload("seq_old_2"), headers=auth_headers)

    # Backdate seq_old_2 to 35 days ago
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)
    item2 = db_session.query(Clipboard).filter_by(clipboard_id="seq_old_2").first()
    item2.updated_at = old_time
    item2.timestamp = old_time
    db_session.commit()

    # Requesting changes since item 1 (change_number 1) when next change (item 2) is older than 30 days -> 410 Gone
    res = client.get("/api/v1/clipboard/sync", params={"since_change_number": item2.change_number - 1}, headers=auth_headers)
    assert res.status_code == 410
    assert "Sync state expired" in res.json()["detail"]

