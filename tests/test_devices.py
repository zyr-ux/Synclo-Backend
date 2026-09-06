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


def test_remote_device_deletion_closes_websocket_with_code_4003(client, user_factory):
    from starlette.websockets import WebSocketDisconnect
    import pytest

    user = user_factory()

    # Register device 2
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "dev_to_be_remotely_deleted",
        "device_name": "Second Phone",
        "os": "Android",
    })
    token_dev2 = dev2_res.json()["access_token"]

    # Device 2 connects to WebSocket
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws_dev2:
        # Device 1 remotely deletes Device 2 via REST
        res_del = client.delete("/api/v1/devices/dev_to_be_remotely_deleted", headers=user["headers"])
        assert res_del.status_code == 200

        # Device 2 should receive 'device_deleted' message and then be disconnected with code 4003
        msg = ws_dev2.receive_json()
        assert msg.get("type") == "device_deleted"
        assert "removed from your account" in msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws_dev2.receive_json()
        assert exc_info.value.code == 4003


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

    # Overly long name (>128 chars rejected by schema or endpoint)
    res_long = client.patch(
        f"/api/v1/devices/{dev_id}",
        json={"device_name": "a" * 129},
        headers=auth_user["headers"]
    )
    assert res_long.status_code in (400, 422)


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


def test_cross_user_shared_device_id_isolation(client, user_factory):
    user_a = user_factory(email="user_a_share@synclo.app", device_id="laptop_primary")
    user_b = user_factory(email="user_b_share@synclo.app", device_id="laptop_secondary")

    shared_dev_id = "shared_family_pc"

    # 1. User A registers the shared device
    res_a = client.post("/api/v1/devices/register", json={
        "device_id": shared_dev_id,
        "device_name": "User A Family PC",
        "os": "Windows 11",
    }, headers=user_a["headers"])
    assert res_a.status_code == 200
    assert res_a.json()["device_id"] == shared_dev_id

    # 2. User B registers the SAME device ID without conflict
    res_b = client.post("/api/v1/devices/register", json={
        "device_id": shared_dev_id,
        "device_name": "User B Family PC",
        "os": "Windows 11",
    }, headers=user_b["headers"])
    assert res_b.status_code == 200
    assert res_b.json()["device_id"] == shared_dev_id

    # 3. User A renames their instance of the shared device
    res_rename = client.patch(f"/api/v1/devices/{shared_dev_id}", json={
        "device_name": "User A Renovated PC",
    }, headers=user_a["headers"])
    assert res_rename.status_code == 200
    assert res_rename.json()["device_name"] == "User A Renovated PC"

    # Verify User B's device name is untouched
    list_b = client.get("/api/v1/devices", headers=user_b["headers"]).json()
    b_dev = next(d for d in list_b if d["device_id"] == shared_dev_id)
    assert b_dev["device_name"] == "User B Family PC"

    # 4. User A deletes their instance of the shared device
    res_del = client.delete(f"/api/v1/devices/{shared_dev_id}", headers=user_a["headers"])
    assert res_del.status_code == 200

    # User B's device is still present and healthy
    list_b_after = client.get("/api/v1/devices", headers=user_b["headers"]).json()
    assert any(d["device_id"] == shared_dev_id for d in list_b_after)

    # 5. User A can log in with the shared device ID again without conflict
    login_a = client.post("/api/v1/login", json={
        "email": user_a["email"],
        "auth_key": user_a["auth_key"],
        "device_id": shared_dev_id,
        "device_name": "User A Logged In",
        "os": "Windows 11",
    })
    assert login_a.status_code == 200

