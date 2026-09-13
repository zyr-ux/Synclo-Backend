"""
Test Suite: Offline Delta Synchronization, Tombstones & Pagination

Scenarios Targeted:
1. Incremental delta sync returning only new/updated entries and deleted tombstones after client's last sync time.
2. Offset and limit based batch pagination across multiple sync items ('limit', 'offset', 'next_offset', 'has_more').
3. Expired sync state rejection returning 410 Gone when 'since' exceeds 30-day tombstone retention period.
"""

import datetime
from sqlalchemy import delete, select


def test_sync_without_since_change_number_returns_422(client, auth_headers):
    # since_change_number is required; missing query param should return 422
    res = client.get("/api/v1/clipboard/sync", headers=auth_headers)
    assert res.status_code == 422


def test_delta_sync_flow_and_tombstones(client, auth_headers, clip_payload):
    # 1. Initial sync before any items -> empty
    res_initial = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_initial.status_code == 200
    assert len(res_initial.json()["entries"]) == 0

    # 2. Add Item A
    item_a_id = "sync_item_a"
    res_a = client.post("/api/v1/clipboard", json=clip_payload(item_a_id), headers=auth_headers)
    assert res_a.status_code == 200

    # 3. Sync since 0 -> returns Item A
    res_sync1 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_sync1.status_code == 200
    sync_data1 = res_sync1.json()
    assert len(sync_data1["entries"]) == 1
    assert sync_data1["entries"][0]["id"] == item_a_id
    cursor1 = sync_data1["next_cursor"]

    # 4. Add Item B
    item_b_id = "sync_item_b"
    client.post("/api/v1/clipboard", json=clip_payload(item_b_id), headers=auth_headers)

    # 5. Sync since cursor1 -> returns only Item B
    res_sync2 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": cursor1}, headers=auth_headers
    )
    assert res_sync2.status_code == 200
    sync_data2 = res_sync2.json()
    assert len(sync_data2["entries"]) == 1
    assert sync_data2["entries"][0]["id"] == item_b_id
    cursor2 = sync_data2["next_cursor"]

    # 6. Delete Item A (creating tombstone)
    client.delete(f"/api/v1/clipboard/{item_a_id}", headers=auth_headers)

    # 7. Sync since cursor2 -> returns tombstone for A
    res_sync3 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": cursor2}, headers=auth_headers
    )
    assert res_sync3.status_code == 200
    sync_data3 = res_sync3.json()
    assert len(sync_data3["entries"]) == 1
    assert sync_data3["entries"][0]["id"] == item_a_id
    assert sync_data3["entries"][0]["is_deleted"] is True
    assert sync_data3["entries"][0]["ciphertext"] is None

    # 8. Sync since 0 -> returns tombstone for A and active B
    res_sync_all = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_sync_all.status_code == 200
    all_entries = {e["id"]: e for e in res_sync_all.json()["entries"]}
    assert len(all_entries) == 2
    assert all_entries[item_a_id]["is_deleted"] is True
    assert all_entries[item_a_id]["ciphertext"] is None
    assert all_entries[item_b_id]["is_deleted"] is False


def test_delta_sync_keyset_cursor_pagination(client, auth_headers, clip_payload):
    # Create 4 items
    for i in range(4):
        client.post(
            "/api/v1/clipboard", json=clip_payload(f"cursor_item_{i}"), headers=auth_headers
        )

    # Page 1: since_change_number=0, limit=2
    r1 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": 0, "limit": 2},
        headers=auth_headers,
    )
    assert r1.status_code == 200
    p1 = r1.json()
    assert [e["id"] for e in p1["entries"]] == ["cursor_item_0", "cursor_item_1"]
    assert p1["has_more"] is True
    assert p1["next_cursor"] is not None
    cursor1 = p1["next_cursor"]

    # Page 2: using cursor1
    r2 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": cursor1, "limit": 2},
        headers=auth_headers,
    )
    assert r2.status_code == 200
    p2 = r2.json()
    assert [e["id"] for e in p2["entries"]] == ["cursor_item_2", "cursor_item_3"]
    cursor2 = p2["next_cursor"]

    # Page 3: using cursor2 -> no more items
    r3 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": cursor2, "limit": 2},
        headers=auth_headers,
    )
    assert r3.status_code == 200
    p3 = r3.json()
    assert len(p3["entries"]) == 0
    assert p3["has_more"] is False
    assert p3["next_cursor"] is None


def test_pin_increments_sync_sequence(client, auth_headers, clip_payload):
    # 1. Create item
    res_create = client.post(
        "/api/v1/clipboard", json=clip_payload("seq_pin_item"), headers=auth_headers
    )
    assert res_create.status_code == 200

    r_sync1 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": 0, "limit": 10},
        headers=auth_headers,
    )
    entries1 = r_sync1.json()["entries"]
    assert len(entries1) >= 1
    seq_before = entries1[-1]["change_number"]

    # 2. Pin item
    res_pin = client.patch(
        "/api/v1/clipboard/seq_pin_item/pin", json={"is_pinned": True}, headers=auth_headers
    )
    assert res_pin.status_code == 200
    assert res_pin.json()["change_number"] > seq_before

    # 3. Sync since seq_before -> should return the pin update!
    r_sync2 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": seq_before, "limit": 10},
        headers=auth_headers,
    )
    entries2 = r_sync2.json()["entries"]
    assert len(entries2) == 1
    assert entries2[0]["id"] == "seq_pin_item"
    assert entries2[0]["is_pinned"] is True


def test_delta_sync_keyset_sequence_410_retention_cutoff(
    client, auth_headers, clip_payload, db_session
):
    from app.database.models import Clipboard

    # 1. Create 3 items
    for i in range(1, 4):
        res = client.post(
            "/api/v1/clipboard", json=clip_payload(f"seq_410_item_{i}"), headers=auth_headers
        )
        assert res.status_code == 200

    from app.database.engine import run_in_write_transaction

    # 2. Hard-purge item 1 and item 2 to simulate expired tombstones cleaned up after 30 days
    def purge():
        db_session.execute(
            delete(Clipboard).where(
                Clipboard.clipboard_id.in_(["seq_410_item_1", "seq_410_item_2"])
            )
        )

    run_in_write_transaction(db_session, purge)
    db_session.expire_all()

    # Client requesting since_change_number=1 (behind oldest_entry.change_number - 1) gets 410 Gone
    res_expired = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 1}, headers=auth_headers
    )
    assert res_expired.status_code == 410
    assert "Sync state expired" in res_expired.json()["detail"]

    # Client requesting since_change_number=2 (at oldest_entry.change_number - 1) succeeds
    res_valid = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 2}, headers=auth_headers
    )
    assert res_valid.status_code == 200
    assert len(res_valid.json()["entries"]) == 1
    assert res_valid.json()["entries"][0]["id"] == "seq_410_item_3"


def test_delta_sync_keyset_sequence_410_when_entries_older_than_retention(
    client, auth_headers, clip_payload, db_session
):
    from app.database.models import Clipboard

    # Create 2 items
    client.post("/api/v1/clipboard", json=clip_payload("seq_old_1"), headers=auth_headers)
    client.post("/api/v1/clipboard", json=clip_payload("seq_old_2"), headers=auth_headers)

    # Backdate seq_old_2 to 35 days ago
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)
    item2 = db_session.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == "seq_old_2")
    ).first()
    item2.updated_at = old_time
    item2.timestamp = old_time
    db_session.commit()

    # Requesting changes since item 1 (change_number 1) when next change (item 2) is older than 30 days -> 410 Gone
    res = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": item2.change_number - 1},
        headers=auth_headers,
    )
    assert res.status_code == 410
    assert "Sync state expired" in res.json()["detail"]
