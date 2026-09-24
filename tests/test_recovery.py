# Test Suite: Zero-Knowledge Account Recovery, Key Rotation & Timing Parity

import base64
import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.database.models import User
from tests.conftest import generate_random_base64, make_clipboard_payload


# 1. Zero-knowledge registration persisting mandatory recovery wrapped key and hashed verifier.
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

    db_user = db_session.scalars(select(User).where(User.email == email)).first()
    assert db_user is not None
    assert db_user.recovery_wrapped_master_key == base64.b64decode(wrapped_mk)
    assert db_user.recovery_key_verifier != verifier
    assert db_user.recovery_key_verifier.startswith("$2")


# 2. Registration schema rejection when recovery wrapped master key is missing (422).
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


# 3. Registration schema rejection when recovery key verifier is missing (422).
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


# 4. Recovery material endpoint returns wrapped master key without exposing secrets.
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


# 5. Recovery material request with nonexistent email returns 401 generic error.
def test_recovery_material_nonexistent_email(client):
    res = client.post("/api/v1/auth/recovery-material", json={"email": "nobody@synclo.app"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Could not recover account"


# 6. Account recovery attempt with invalid verifier returns 401 generic error.
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


# 7. Account recovery preserves user's encrypted clipboard data and pinned items intact.
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


# 8. Account recovery burns used verifier and automatically rotates recovery key material.
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

    res_burned = client.post("/api/v1/auth/recover", json=recover_payload_1)
    assert res_burned.status_code == 401

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


# 9. Account recovery schema rejection when new rotation key material is omitted (422).
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


# 10. Account recovery terminates existing sessions and revokes all active refresh tokens.
def test_account_recovery_revokes_old_sessions(client, user_factory):
    user = user_factory()
    dev1_refresh = user["refresh_token"]

    login_dev2 = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_02",
            "device_name": "Second Device",
        },
    )
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

    ref1 = client.post("/api/v1/refresh", json={"refresh_token": dev1_refresh})
    assert ref1.status_code == 401

    ref2 = client.post("/api/v1/refresh", json={"refresh_token": dev2_refresh})
    assert ref2.status_code == 401


# 11. Authenticated manual recovery key rotation updates material and invalidates old verifier.
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

    res_mat = client.post("/api/v1/auth/recovery-material", json={"email": user["email"]})
    assert res_mat.status_code == 200
    assert res_mat.json()["recovery_wrapped_master_key"] == new_wrapped

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


# 12. Manual recovery key rotation endpoint rejects unauthenticated requests (401).
def test_manual_recovery_key_rotation_unauthenticated(client):
    res = client.post(
        "/api/v1/auth/recovery-key/rotate",
        json={
            "new_recovery_wrapped_master_key": generate_random_base64(32),
            "new_recovery_key_verifier": generate_random_base64(32),
        },
    )
    assert res.status_code == 401


# 13. Password change rotates recovery wrapped master key and updates verifier.
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

    res_mat = client.post("/api/v1/auth/recovery-material", json={"email": user["email"]})
    assert res_mat.status_code == 200
    assert res_mat.json()["recovery_wrapped_master_key"] == new_wrapped

    res_old = client.post(
        "/api/v1/auth/recover",
        json={
            "email": user["email"],
            "recovery_key_verifier": old_verifier,
            "new_auth_key": generate_random_base64(32),
            "new_encrypted_master_key": generate_random_base64(32),
            "new_salt": generate_random_base64(32),
            "new_kdf_version": 1,
            "new_recovery_wrapped_master_key": generate_random_base64(32),
            "new_recovery_key_verifier": generate_random_base64(32),
            "device_id": "dev_chk",
        },
    )
    assert res_old.status_code == 401

    res_new = client.post(
        "/api/v1/auth/recover",
        json={
            "email": user["email"],
            "recovery_key_verifier": new_verifier,
            "new_auth_key": generate_random_base64(32),
            "new_encrypted_master_key": generate_random_base64(32),
            "new_salt": generate_random_base64(32),
            "new_kdf_version": 1,
            "new_recovery_wrapped_master_key": generate_random_base64(32),
            "new_recovery_key_verifier": generate_random_base64(32),
            "device_id": "dev_chk",
        },
    )
    assert res_new.status_code == 200


# 14. Password change preserves existing recovery material when optional rotation fields omitted.
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

    res_rec = client.post(
        "/api/v1/auth/recover",
        json={
            "email": user["email"],
            "recovery_key_verifier": orig_verifier,
            "new_auth_key": generate_random_base64(32),
            "new_encrypted_master_key": generate_random_base64(32),
            "new_salt": generate_random_base64(32),
            "new_kdf_version": 1,
            "new_recovery_wrapped_master_key": generate_random_base64(32),
            "new_recovery_key_verifier": generate_random_base64(32),
            "device_id": "dev_chk",
        },
    )
    assert res_rec.status_code == 200


# 15. Password change rejects partial recovery key rotation fields (400).
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


# 16. Password change rejects incorrect current password auth key (401).
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


# 17. Account recovery validates base64 formatting, min lengths, and supported KDF version.
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


# 18. Account recovery immediately terminates active WebSocket connections with code 4004.
def test_recovery_disconnects_active_websockets(client, user_factory):
    user = user_factory()
    token = user["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
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


# 19. Dummy verifier check enforces timing parity to prevent user enumeration via recovery.
@pytest.mark.slow
def test_recovery_nonexistent_email_timing_parity(client, user_factory):
    import time

    user = user_factory()
    invalid_verifier = generate_random_base64(32)

    payload_existing = {
        "email": user["email"],
        "recovery_key_verifier": invalid_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "timing_dev_1",
    }
    t0 = time.perf_counter()
    res1 = client.post("/api/v1/auth/recover", json=payload_existing)
    t_existing = time.perf_counter() - t0
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Could not recover account"

    payload_nonexistent = {
        "email": "nonexistent_recovery_target@synclo.app",
        "recovery_key_verifier": invalid_verifier,
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
        "device_id": "timing_dev_2",
    }
    t0 = time.perf_counter()
    res2 = client.post("/api/v1/auth/recover", json=payload_nonexistent)
    t_nonexistent = time.perf_counter() - t0
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Could not recover account"

    assert t_existing > 0.01
    assert t_nonexistent > 0.01
    ratio = max(t_existing, t_nonexistent) / min(t_existing, t_nonexistent)
    assert ratio <= 3.0, (
        f"Timing divergence ratio {ratio:.2f} exceeded 3.0x limit "
        f"(existing={t_existing:.4f}s, nonexistent={t_nonexistent:.4f}s)"
    )
