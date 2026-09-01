"""
Test Suite: Offline Delta Synchronization, Tombstones & Pagination

Scenarios Targeted:
1. Incremental delta sync returning only new/updated entries and deleted tombstones after client's last sync time.
2. Offset and limit based batch pagination across multiple sync items ('limit', 'offset', 'next_offset', 'has_more').
3. Expired sync state rejection returning 410 Gone when 'since' exceeds 30-day tombstone retention period.
"""

import datetime


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


def test_delta_sync_pagination(client, auth_headers, clip_payload):
    # Insert 5 items
    for i in range(5):
        client.post("/api/v1/clipboard",
                    json=clip_payload(f"page_item_{i}"), headers=auth_headers)

    # Fetch page 1 (limit 2, offset 0)
    page1 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": 0}, headers=auth_headers).json()
    assert len(page1["entries"]) == 2
    assert page1["total_count"] == 5
    assert page1["next_offset"] == 2
    assert page1["has_more"] is True

    # Fetch page 2 (limit 2, offset 2)
    page2 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": page1["next_offset"]}, headers=auth_headers).json()
    assert len(page2["entries"]) == 2
    assert page2["total_count"] == 5
    assert page2["next_offset"] == 4
    assert page2["has_more"] is True

    # Fetch page 3 (limit 2, offset 4) -> 1 remaining
    page3 = client.get("/api/v1/clipboard/sync", params={"limit": 2, "offset": page2["next_offset"]}, headers=auth_headers).json()
    assert len(page3["entries"]) == 1
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
