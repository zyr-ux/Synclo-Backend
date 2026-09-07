import base64
import pytest
from starlette.websockets import WebSocketDisconnect

from app.models.models import User
from tests.conftest import generate_random_base64, make_clipboard_payload


def test_register_with_mandatory_recovery_key_and_verifier(client, db_session):
    email = "mandatory_rec@synclo.app"
    auth_key = generate_random_base64(32)
    enc_mk = generate_random_base64(32)
    salt = generate_random_base64(32)
    wrapped_mk = generate_random_base64(32)
    verifier = generate_random_base64(32)

    payload = {
        "email": email,
        "username": "rec_user",
        "auth_key": auth_key,
        "device_id": "rec_dev_01",
        "device_name": "Rec Device",
        "os": "Linux",
        "encrypted_master_key": enc_mk,
        "salt": salt,
        "kdf_version": 1,
        "recovery_wrapped_master_key": wrapped_mk,
        "recovery_key_verifier": verifier,
    }

    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data

    db_user = db_session.query(User).filter(User.email == email).first()
    assert db_user is not None
    assert db_user.recovery_wrapped_master_key == base64.b64decode(wrapped_mk)
    assert db_user.recovery_key_verifier != verifier
    assert db_user.recovery_key_verifier.startswith("$2")


def test_register_missing_recovery_key_fails(client):
    payload = {
        "email": "missing_rec_key@synclo.app",
        "auth_key": generate_random_base64(32),
        "device_id": "dev_01",
        "encrypted_master_key": generate_random_base64(32),
        "salt": generate_random_base64(32),
        "kdf_version": 1,
        "recovery_key_verifier": generate_random_base64(32),
    }
    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 422


def test_register_missing_recovery_verifier_fails(client):
    payload = {
        "email": "missing_rec_ver@synclo.app",
        "auth_key": generate_random_base64(32),
        "device_id": "dev_01",
        "encrypted_master_key": generate_random_base64(32),
        "salt": generate_random_base64(32),
        "kdf_version": 1,
        "recovery_wrapped_master_key": generate_random_base64(32),
    }
    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 422


def test_recovery_material_returns_only_wrapped_key(client, user_factory):
    user = user_factory()
    res = client.post("/api/v1/auth/recovery-material", json={"email": user["email"]})
    assert res.status_code == 200
    data = res.json()
    assert "recovery_wrapped_master_key" in data
    assert data["recovery_wrapped_master_key"] == user["recovery_wrapped_master_key"]
    assert "salt" not in data
    assert "kdf_version" not in data
    assert "recovery_key_verifier" not in data


def test_recovery_material_nonexistent_email(client):
    res = client.post("/api/v1/auth/recovery-material", json={"email": "nobody@synclo.app"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Could not recover account"


def test_account_recovery_invalid_verifier_rejected(client, user_factory):
    user = user_factory()
    payload = {
        "email": user["email"],
        "recovery_key_verifier": generate_random_base64(32),
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "recovered_dev_01",
    }
    res = client.post("/api/v1/auth/recover", json=payload)
    assert res.status_code == 401
    assert res.json()["detail"] == "Could not recover account"


def test_account_recovery_flow_preserves_clipboard(client, user_factory):
    user = user_factory()
    headers = user["headers"]

    clip_payload = make_clipboard_payload("clip_item_preserve", is_pinned=True)
    res_clip = client.post("/api/v1/clipboard", json=clip_payload, headers=headers)
    assert res_clip.status_code == 200

    new_auth_key = generate_random_base64(32)
    recover_payload = {
        "email": user["email"],
        "recovery_key_verifier": user["recovery_key_verifier"],
        "new_auth_key": new_auth_key,
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "recovered_device_id",
        "device_name": "Recovered Device",
        "os": "MacOS",
    }

    res_rec = client.post("/api/v1/auth/recover", json=recover_payload)
    assert res_rec.status_code == 200
    rec_data = res_rec.json()
    assert "access_token" in rec_data

    new_headers = {"Authorization": f"Bearer {rec_data['access_token']}"}
    res_fetch = client.get("/api/v1/clipboard/clip_item_preserve", headers=new_headers)
    assert res_fetch.status_code == 200
    item = res_fetch.json()
    assert item["id"] == "clip_item_preserve"
    assert item["is_pinned"] is True


def test_account_recovery_auto_rotates_recovery_key(client, user_factory):
    user = user_factory()
    old_verifier = user["recovery_key_verifier"]
    new_verifier_1 = generate_random_base64(32)
    new_wrapped_mk_1 = generate_random_base64(32)

    recover_payload_1 = {
        "email": user["email"],
        "recovery_key_verifier": old_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": new_wrapped_mk_1,
        "new_recovery_key_verifier": new_verifier_1,
        "device_id": "dev_rec_1",
    }

    res1 = client.post("/api/v1/auth/recover", json=recover_payload_1)
    assert res1.status_code == 200

    # Burning verification: old verifier must be rejected
    res_burned = client.post("/api/v1/auth/recover", json=recover_payload_1)
    assert res_burned.status_code == 401

    # New verifier must succeed on next recovery
    new_verifier_2 = generate_random_base64(32)
    recover_payload_2 = {
        "email": user["email"],
        "recovery_key_verifier": new_verifier_1,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": new_verifier_2,
        "device_id": "dev_rec_2",
    }
    res2 = client.post("/api/v1/auth/recover", json=recover_payload_2)
    assert res2.status_code == 200


def test_account_recovery_missing_new_recovery_key_fails(client, user_factory):
    user = user_factory()
    payload = {
        "email": user["email"],
        "recovery_key_verifier": user["recovery_key_verifier"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "device_id": "dev_rec",
    }
    res = client.post("/api/v1/auth/recover", json=payload)
    assert res.status_code == 422


def test_account_recovery_revokes_old_sessions(client, user_factory):
    user = user_factory()
    dev1_refresh = user["refresh_token"]

    login_dev2 = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "dev_02",
        "device_name": "Second Device",
    })
    assert login_dev2.status_code == 200
    dev2_refresh = login_dev2.json()["refresh_token"]

    recover_payload = {
        "email": user["email"],
        "recovery_key_verifier": user["recovery_key_verifier"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_03",
    }
    res_rec = client.post("/api/v1/auth/recover", json=recover_payload)
    assert res_rec.status_code == 200

    # Old refresh tokens should fail
    ref1 = client.post("/api/v1/refresh", json={"refresh_token": dev1_refresh})
    assert ref1.status_code == 401

    ref2 = client.post("/api/v1/refresh", json={"refresh_token": dev2_refresh})
    assert ref2.status_code == 401


def test_manual_recovery_key_rotation_endpoint(client, user_factory):
    user = user_factory()
    old_verifier = user["recovery_key_verifier"]
    new_wrapped = generate_random_base64(32)
    new_verifier = generate_random_base64(32)

    res_rotate = client.post(
        "/api/v1/auth/recovery-key/rotate",
        json={
            "new_recovery_wrapped_master_key": new_wrapped,
            "new_recovery_key_verifier": new_verifier,
        },
        headers=user["headers"],
    )
    assert res_rotate.status_code == 200
    assert res_rotate.json()["message"] == "Recovery key regenerated and updated successfully"

    # Verify recovery material endpoint returns new wrapped key
    res_mat = client.post("/api/v1/auth/recovery-material", json={"email": user["email"]})
    assert res_mat.status_code == 200
    assert res_mat.json()["recovery_wrapped_master_key"] == new_wrapped

    # Verify old verifier no longer works
    fail_payload = {
        "email": user["email"],
        "recovery_key_verifier": old_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_test",
    }
    assert client.post("/api/v1/auth/recover", json=fail_payload).status_code == 401

    # Verify new verifier works
    succ_payload = {
        "email": user["email"],
        "recovery_key_verifier": new_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_test_2",
    }
    assert client.post("/api/v1/auth/recover", json=succ_payload).status_code == 200


def test_manual_recovery_key_rotation_unauthenticated(client):
    res = client.post("/api/v1/auth/recovery-key/rotate", json={
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
    })
    assert res.status_code == 401


def test_password_change_rotates_recovery_key_and_verifier(client, user_factory):
    user = user_factory()
    old_verifier = user["recovery_key_verifier"]
    new_auth_key = generate_random_base64(32)
    new_wrapped = generate_random_base64(32)
    new_verifier = generate_random_base64(32)

    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": new_auth_key,
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": new_wrapped,
        "new_recovery_key_verifier": new_verifier,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 200

    # Recovery material now returns new wrapped key
    res_mat = client.post("/api/v1/auth/recovery-material", json={"email": user["email"]})
    assert res_mat.status_code == 200
    assert res_mat.json()["recovery_wrapped_master_key"] == new_wrapped

    # Old verifier rejected
    res_old = client.post("/api/v1/auth/recover", json={
        "email": user["email"],
        "recovery_key_verifier": old_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_chk",
    })
    assert res_old.status_code == 401

    # New verifier accepted
    res_new = client.post("/api/v1/auth/recover", json={
        "email": user["email"],
        "recovery_key_verifier": new_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_chk",
    })
    assert res_new.status_code == 200


def test_password_change_preserves_recovery_key(client, user_factory):
    user = user_factory()
    orig_verifier = user["recovery_key_verifier"]
    new_auth_key = generate_random_base64(32)

    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": new_auth_key,
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 200

    # Original verifier still valid for recovery
    res_rec = client.post("/api/v1/auth/recover", json={
        "email": user["email"],
        "recovery_key_verifier": orig_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_chk",
    })
    assert res_rec.status_code == 200


def test_password_change_partial_recovery_fields_rejected(client, user_factory):
    user = user_factory()
    base_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }

    p1 = {**base_payload, "new_recovery_wrapped_master_key": generate_random_base64(32)}
    res1 = client.post("/api/v1/password/change", json=p1, headers=user["headers"])
    assert res1.status_code == 400

    p2 = {**base_payload, "new_recovery_key_verifier": generate_random_base64(32)}
    res2 = client.post("/api/v1/password/change", json=p2, headers=user["headers"])
    assert res2.status_code == 400


def test_password_change_wrong_current_password_rejected(client, user_factory):
    user = user_factory()
    change_payload = {
        "old_auth_key": generate_random_base64(32),
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 401
    assert res.json()["detail"] == "Incorrect current password"


def test_recovery_validation_failures(client, user_factory):
    user = user_factory()
    base_valid = {
        "email": user["email"],
        "recovery_key_verifier": user["recovery_key_verifier"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "dev_valid",
    }

    bad_b64 = {**base_valid, "recovery_key_verifier": "!!!not_base64!!!"}
    assert client.post("/api/v1/auth/recover", json=bad_b64).status_code == 400

    short_auth = {**base_valid, "new_auth_key": base64.b64encode(b"short").decode("utf-8")}
    assert client.post("/api/v1/auth/recover", json=short_auth).status_code == 400

    short_dev = {**base_valid, "device_id": "ab"}
    assert client.post("/api/v1/auth/recover", json=short_dev).status_code == 400

    long_dev_name = {**base_valid, "device_name": "a" * 129}
    assert client.post("/api/v1/auth/recover", json=long_dev_name).status_code in (400, 422)

    bad_kdf = {**base_valid, "new_kdf_version": 99}
    assert client.post("/api/v1/auth/recover", json=bad_kdf).status_code == 400


def test_recovery_disconnects_active_websockets(client, user_factory):
    user = user_factory()
    token = user["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        recover_payload = {
            "email": user["email"],
            "recovery_key_verifier": user["recovery_key_verifier"],
            "new_auth_key": generate_random_base64(32),
            "new_encrypted_master_key": generate_random_base64(32),
            "new_salt": generate_random_base64(32),
            "new_kdf_version": 1,
            "new_recovery_wrapped_master_key": generate_random_base64(32),
            "new_recovery_key_verifier": generate_random_base64(32),
            "device_id": "recovered_dev_ws",
        }
        res = client.post("/api/v1/auth/recover", json=recover_payload)
        assert res.status_code == 200

        msg = ws.receive_json()
        assert msg.get("type") == "session_invalidated"
        assert msg.get("reason") == "credentials_changed"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 4004
