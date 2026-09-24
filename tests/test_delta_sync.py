# Test Suite: Offline Delta Synchronization, Tombstones & Pagination

import datetime
from sqlalchemy import delete, select


# 1. Reject delta sync request missing mandatory since_change_number query parameter (422).
def test_sync_without_since_change_number_returns_422(client, auth_headers):
    res = client.get("/api/v1/clipboard/sync", headers=auth_headers)
    assert res.status_code == 422


# 2. Incremental delta sync returning new entries and deleted tombstones after client cursor.
def test_delta_sync_flow_and_tombstones(client, auth_headers, clip_payload):
    res_initial = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_initial.status_code == 200
    assert len(res_initial.json()["entries"]) == 0

    item_a_id = "sync_item_a"
    res_a = client.post("/api/v1/clipboard", json=clip_payload(item_a_id), headers=auth_headers)
    assert res_a.status_code == 200

    res_sync1 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_sync1.status_code == 200
    sync_data1 = res_sync1.json()
    assert len(sync_data1["entries"]) == 1
    assert sync_data1["entries"][0]["id"] == item_a_id
    cursor1 = sync_data1["next_cursor"]

    item_b_id = "sync_item_b"
    client.post("/api/v1/clipboard", json=clip_payload(item_b_id), headers=auth_headers)

    res_sync2 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": cursor1}, headers=auth_headers
    )
    assert res_sync2.status_code == 200
    sync_data2 = res_sync2.json()
    assert len(sync_data2["entries"]) == 1
    assert sync_data2["entries"][0]["id"] == item_b_id
    cursor2 = sync_data2["next_cursor"]

    client.delete(f"/api/v1/clipboard/{item_a_id}", headers=auth_headers)

    res_sync3 = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": cursor2}, headers=auth_headers
    )
    assert res_sync3.status_code == 200
    sync_data3 = res_sync3.json()
    assert len(sync_data3["entries"]) == 1
    assert sync_data3["entries"][0]["id"] == item_a_id
    assert sync_data3["entries"][0]["is_deleted"] is True
    assert sync_data3["entries"][0]["ciphertext"] is None

    res_sync_all = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    assert res_sync_all.status_code == 200
    all_entries = {e["id"]: e for e in res_sync_all.json()["entries"]}
    assert len(all_entries) == 2
    assert all_entries[item_a_id]["is_deleted"] is True
    assert all_entries[item_a_id]["ciphertext"] is None
    assert all_entries[item_b_id]["is_deleted"] is False


# 3. Keyset cursor pagination over delta sync entries using next_cursor and has_more flag.
def test_delta_sync_keyset_cursor_pagination(client, auth_headers, clip_payload):
    for i in range(4):
        client.post(
            "/api/v1/clipboard", json=clip_payload(f"cursor_item_{i}"), headers=auth_headers
        )

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

    r2 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": cursor1, "limit": 2},
        headers=auth_headers,
    )
    assert r2.status_code == 200
    p2 = r2.json()
    assert [e["id"] for e in p2["entries"]] == ["cursor_item_2", "cursor_item_3"]
    cursor2 = p2["next_cursor"]

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


# 4. Pin state update increments change sequence number and delivers delta update.
def test_pin_increments_sync_sequence(client, auth_headers, clip_payload):
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

    res_pin = client.patch(
        "/api/v1/clipboard/seq_pin_item/pin", json={"is_pinned": True}, headers=auth_headers
    )
    assert res_pin.status_code == 200
    assert res_pin.json()["change_number"] > seq_before

    r_sync2 = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": seq_before, "limit": 10},
        headers=auth_headers,
    )
    entries2 = r_sync2.json()["entries"]
    assert len(entries2) == 1
    assert entries2[0]["id"] == "seq_pin_item"
    assert entries2[0]["is_pinned"] is True


# 5. Keyset sequence retention cutoff returns 410 Gone when cursor predates surviving tombstones.
def test_delta_sync_keyset_sequence_410_retention_cutoff(
    client, auth_headers, clip_payload, db_session
):
    from app.database.models import Clipboard

    for i in range(1, 4):
        res = client.post(
            "/api/v1/clipboard", json=clip_payload(f"seq_410_item_{i}"), headers=auth_headers
        )
        assert res.status_code == 200

    sync_res = client.get(
        "/api/v1/clipboard/sync", params={"since_change_number": 0}, headers=auth_headers
    )
    item3_cn = next(
        e["change_number"] for e in sync_res.json()["entries"] if e["id"] == "seq_410_item_3"
    )

    from app.database.engine import run_in_write_transaction

    def purge():
        db_session.execute(
            delete(Clipboard).where(
                Clipboard.clipboard_id.in_(["seq_410_item_1", "seq_410_item_2"])
            )
        )

    run_in_write_transaction(db_session, purge)
    db_session.expire_all()

    expired_cursor = item3_cn - 2
    res_expired = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": expired_cursor},
        headers=auth_headers,
    )
    assert res_expired.status_code == 410
    assert "Sync state expired" in res_expired.json()["detail"]

    valid_cursor = item3_cn - 1
    res_valid = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": valid_cursor},
        headers=auth_headers,
    )
    assert res_valid.status_code == 200
    assert len(res_valid.json()["entries"]) == 1
    assert res_valid.json()["entries"][0]["id"] == "seq_410_item_3"


# 6. Reject delta sync with 410 Gone when requested change number refers to expired entries.
def test_delta_sync_keyset_sequence_410_when_entries_older_than_retention(
    client, auth_headers, clip_payload, db_session
):
    from app.database.models import Clipboard

    client.post("/api/v1/clipboard", json=clip_payload("seq_old_1"), headers=auth_headers)
    client.post("/api/v1/clipboard", json=clip_payload("seq_old_2"), headers=auth_headers)

    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)
    item2 = db_session.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == "seq_old_2")
    ).first()
    item2.updated_at = old_time
    item2.timestamp = old_time
    db_session.commit()

    res = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": item2.change_number - 1},
        headers=auth_headers,
    )
    assert res.status_code == 410
    assert "Sync state expired" in res.json()["detail"]


# 7. Delta sync succeeds without 410 when next change is an aged pinned item immune to retention.
def test_delta_sync_does_not_410_when_next_entry_is_old_pinned_item(
    client, auth_headers, clip_payload, db_session
):
    from app.database.models import Clipboard

    client.post("/api/v1/clipboard", json=clip_payload("seq_pinned_1"), headers=auth_headers)
    client.post(
        "/api/v1/clipboard",
        json=clip_payload("seq_pinned_2", is_pinned=True),
        headers=auth_headers,
    )

    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)
    item2 = db_session.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == "seq_pinned_2")
    ).first()
    item2.updated_at = old_time
    item2.timestamp = old_time
    db_session.commit()

    res = client.get(
        "/api/v1/clipboard/sync",
        params={"since_change_number": item2.change_number - 1},
        headers=auth_headers,
    )
    assert res.status_code == 200
    entries = res.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["id"] == "seq_pinned_2"
    assert entries[0]["is_pinned"] is True
