"""
Test Suite: Device Management, Metadata & Revocation

Scenarios Targeted:
1. Device registration with OS platform metadata and listing via 'GET /api/v1/devices'.
2. Explicit device deletion via 'DELETE /api/v1/devices/{id}'.
3. Cross-tenant isolation (preventing deleting another user's device, returning 404).
4. Real-time online presence detection and immediate token revocation (403 Forbidden).
"""


def test_device_registration_and_list(client, auth_user):
    # Check default registered device
    res = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res.status_code == 200
    devices = res.json()
    assert len(devices) == 1
    assert devices[0]["device_id"] == auth_user["device_id"]
    assert devices[0]["os"] == auth_user["os"]

    # Register second device
    dev2_payload = {
        "device_id": "second_device_phone",
        "device_name": "Pixel 8",
        "os": "Android 14",
    }
    res_reg = client.post("/api/v1/devices/register", json=dev2_payload, headers=auth_user["headers"])
    assert res_reg.status_code == 200
    reg_data = res_reg.json()
    assert reg_data["device_id"] == "second_device_phone"
    assert reg_data["os"] == "Android 14"

    # List again -> 2 devices
    res2 = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res2.status_code == 200
    assert len(res2.json()) == 2


def test_device_deletion_and_revocation(client, auth_user):
    # Register another device
    dev_payload = {
        "device_id": "device_to_delete",
        "device_name": "Old Tablet",
        "os": "iOS 17",
    }
    client.post("/api/v1/devices/register", json=dev_payload, headers=auth_user["headers"])

    # Delete device
    res_del = client.delete("/api/v1/devices/device_to_delete", headers=auth_user["headers"])
    assert res_del.status_code == 200

    # Ensure device is gone
    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    dev_ids = [d["device_id"] for d in res_list.json()]
    assert "device_to_delete" not in dev_ids


def test_cannot_delete_other_user_device(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.delete(f"/api/v1/devices/{other_user['device_id']}", headers=auth_user["headers"])
    assert res.status_code == 404


def test_device_online_presence_and_token_invalidation(client, user_factory):
    user = user_factory()

    # 1. Device 1 connects to WebSocket
    with client.websocket_connect("/ws/v1/sync", headers=user["headers"]) as ws:
        # Check presence -> is_online should be True
        res = client.get("/api/v1/devices", headers=user["headers"])
        assert res.status_code == 200
        devices = res.json()
        dev = next(d for d in devices if d["device_id"] == user["device_id"])
        assert dev["is_online"] is True

    # 2. After disconnect -> is_online is False
    res_after = client.get("/api/v1/devices", headers=user["headers"])
    dev_after = next(d for d in res_after.json() if d["device_id"] == user["device_id"])
    assert dev_after["is_online"] is False

    # 3. Delete the device -> token should now be unauthorized (403)
    del_res = client.delete(f"/api/v1/devices/{user['device_id']}", headers=user["headers"])
    assert del_res.status_code == 200

    auth_check = client.get("/api/v1/devices", headers=user["headers"])
    assert auth_check.status_code == 403


def test_rename_device_success(client, auth_user):
    dev_id = auth_user["device_id"]
    res = client.patch(
        f"/api/v1/devices/{dev_id}",
        json={"device_name": "Workstation Pro"},
        headers=auth_user["headers"]
    )
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] == dev_id
    assert data["device_name"] == "Workstation Pro"

    # Verify updated in listing
    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res_list.status_code == 200
    devices = res_list.json()
    matched = next(d for d in devices if d["device_id"] == dev_id)
    assert matched["device_name"] == "Workstation Pro"


def test_rename_device_validation_errors(client, auth_user):
    dev_id = auth_user["device_id"]
    # Empty / whitespace-only name
    res_empty = client.patch(
        f"/api/v1/devices/{dev_id}",
        json={"device_name": "   "},
        headers=auth_user["headers"]
    )
    assert res_empty.status_code == 400

    # Overly long name (>128 chars)
    res_long = client.patch(
        f"/api/v1/devices/{dev_id}",
        json={"device_name": "a" * 129},
        headers=auth_user["headers"]
    )
    assert res_long.status_code == 400


def test_cannot_rename_other_user_device(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.patch(
        f"/api/v1/devices/{other_user['device_id']}",
        json={"device_name": "Hijacked Device"},
        headers=auth_user["headers"]
    )
    assert res.status_code == 404


def test_rename_non_existent_device(client, auth_user):
    res = client.patch(
        "/api/v1/devices/non_existent_device_id_123",
        json={"device_name": "Ghost Device"},
        headers=auth_user["headers"]
    )
    assert res.status_code == 404
