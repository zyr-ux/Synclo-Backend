# Test Suite: Device Management, Metadata & Revocation

from starlette.websockets import WebSocketDisconnect
import pytest


# 1. Device registration with OS platform metadata and listing via 'GET /api/v1/devices'.
def test_device_registration_and_list(client, auth_user):
    res = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res.status_code == 200
    devices = res.json()
    assert len(devices) == 1
    assert devices[0]["device_id"] == auth_user["device_id"]
    assert devices[0]["os"] == auth_user["os"]

    dev2_payload = {
        "device_id": "second_device_phone",
        "device_name": "Pixel 8",
        "os": "Android 14",
    }
    res_reg = client.post(
        "/api/v1/devices/register", json=dev2_payload, headers=auth_user["headers"]
    )
    assert res_reg.status_code == 200
    reg_data = res_reg.json()
    assert reg_data["device_id"] == "second_device_phone"
    assert reg_data["os"] == "Android 14"

    res2 = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res2.status_code == 200
    assert len(res2.json()) == 2


# 2. Explicit device deletion via 'DELETE /api/v1/devices/{id}'.
def test_device_deletion_and_revocation(client, auth_user):
    dev_payload = {
        "device_id": "device_to_delete",
        "device_name": "Old Tablet",
        "os": "iOS 17",
    }
    client.post("/api/v1/devices/register", json=dev_payload, headers=auth_user["headers"])

    res_del = client.delete("/api/v1/devices/device_to_delete", headers=auth_user["headers"])
    assert res_del.status_code == 200

    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    dev_ids = [d["device_id"] for d in res_list.json()]
    assert "device_to_delete" not in dev_ids


# 3. Cross-tenant isolation preventing deleting another user's device (404).
def test_cannot_delete_other_user_device(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.delete(f"/api/v1/devices/{other_user['device_id']}", headers=auth_user["headers"])
    assert res.status_code == 404


# 4. Real-time online presence detection and immediate token revocation (403 Forbidden).
def test_device_online_presence_and_token_invalidation(client, user_factory):
    user = user_factory()

    with client.websocket_connect("/ws/v1/sync", headers=user["headers"]):
        res = client.get("/api/v1/devices", headers=user["headers"])
        assert res.status_code == 200
        devices = res.json()
        dev = next(d for d in devices if d["device_id"] == user["device_id"])
        assert dev["is_online"] is True

    res_after = client.get("/api/v1/devices", headers=user["headers"])
    dev_after = next(d for d in res_after.json() if d["device_id"] == user["device_id"])
    assert dev_after["is_online"] is False

    del_res = client.delete(f"/api/v1/devices/{user['device_id']}", headers=user["headers"])
    assert del_res.status_code == 200

    auth_check = client.get("/api/v1/devices", headers=user["headers"])
    assert auth_check.status_code == 403


# 5. Remote device deletion terminating active WebSocket connection with close code 4003.
def test_remote_device_deletion_closes_websocket_with_code_4003(client, user_factory):
    user = user_factory()

    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_to_be_remotely_deleted",
            "device_name": "Second Phone",
            "os": "Android",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws_dev2:
        res_del = client.delete(
            "/api/v1/devices/dev_to_be_remotely_deleted", headers=user["headers"]
        )
        assert res_del.status_code == 200

        msg = ws_dev2.receive_json()
        assert msg.get("type") == "device_deleted"
        assert "removed from your account" in msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws_dev2.receive_json()
        assert exc_info.value.code == 4003


# 6. In-place device rename via 'PATCH /api/v1/devices/{id}' and listing reflection.
def test_rename_device_success(client, auth_user):
    dev_id = auth_user["device_id"]
    res = client.patch(
        f"/api/v1/devices/{dev_id}",
        json={"device_name": "Workstation Pro"},
        headers=auth_user["headers"],
    )
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] == dev_id
    assert data["device_name"] == "Workstation Pro"

    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res_list.status_code == 200
    devices = res_list.json()
    matched = next(d for d in devices if d["device_id"] == dev_id)
    assert matched["device_name"] == "Workstation Pro"


# 7. Device rename rejection on empty whitespace (400) or oversized name (422).
def test_rename_device_validation_errors(client, auth_user):
    dev_id = auth_user["device_id"]
    res_empty = client.patch(
        f"/api/v1/devices/{dev_id}", json={"device_name": "   "}, headers=auth_user["headers"]
    )
    assert res_empty.status_code == 400

    res_long = client.patch(
        f"/api/v1/devices/{dev_id}", json={"device_name": "a" * 129}, headers=auth_user["headers"]
    )
    assert res_long.status_code == 422


# 8. Cross-tenant isolation preventing renaming another user's device (404).
def test_cannot_rename_other_user_device(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.patch(
        f"/api/v1/devices/{other_user['device_id']}",
        json={"device_name": "Hijacked Device"},
        headers=auth_user["headers"],
    )
    assert res.status_code == 404


# 9. Device rename rejection when targeting nonexistent device identifier (404).
def test_rename_non_existent_device(client, auth_user):
    res = client.patch(
        "/api/v1/devices/non_existent_device_id_123",
        json={"device_name": "Ghost Device"},
        headers=auth_user["headers"],
    )
    assert res.status_code == 404


# 10. Multi-user shared physical device ID isolation across register, rename, and delete lifecycle.
def test_cross_user_shared_device_id_isolation(client, user_factory):
    user_a = user_factory(email="user_a_share@synclo.app", device_id="laptop_primary")
    user_b = user_factory(email="user_b_share@synclo.app", device_id="laptop_secondary")

    shared_dev_id = "shared_family_pc"

    res_a = client.post(
        "/api/v1/devices/register",
        json={
            "device_id": shared_dev_id,
            "device_name": "User A Family PC",
            "os": "Windows 11",
        },
        headers=user_a["headers"],
    )
    assert res_a.status_code == 200
    assert res_a.json()["device_id"] == shared_dev_id

    res_b = client.post(
        "/api/v1/devices/register",
        json={
            "device_id": shared_dev_id,
            "device_name": "User B Family PC",
            "os": "Windows 11",
        },
        headers=user_b["headers"],
    )
    assert res_b.status_code == 200
    assert res_b.json()["device_id"] == shared_dev_id

    res_rename = client.patch(
        f"/api/v1/devices/{shared_dev_id}",
        json={
            "device_name": "User A Renovated PC",
        },
        headers=user_a["headers"],
    )
    assert res_rename.status_code == 200
    assert res_rename.json()["device_name"] == "User A Renovated PC"

    list_b = client.get("/api/v1/devices", headers=user_b["headers"]).json()
    b_dev = next(d for d in list_b if d["device_id"] == shared_dev_id)
    assert b_dev["device_name"] == "User B Family PC"

    res_del = client.delete(f"/api/v1/devices/{shared_dev_id}", headers=user_a["headers"])
    assert res_del.status_code == 200

    list_b_after = client.get("/api/v1/devices", headers=user_b["headers"]).json()
    assert any(d["device_id"] == shared_dev_id for d in list_b_after)

    login_a = client.post(
        "/api/v1/login",
        json={
            "email": user_a["email"],
            "auth_key": user_a["auth_key"],
            "device_id": shared_dev_id,
            "device_name": "User A Logged In",
            "os": "Windows 11",
        },
    )
    assert login_a.status_code == 200
