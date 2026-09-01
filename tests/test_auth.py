"""
Test Suite: Authentication, Zero-Knowledge Key Exchange & Account Lifecycle

Scenarios Targeted:
1. Zero-knowledge registration and multi-device login returning E2EE key material.
2. Duplicate email registration rejection (409 Conflict).
3. Public pre-login salt & KDF version retrieval via '/api/v1/auth/salt'.
4. User profile inspection via authenticated 'GET /api/v1/user'.
5. In-place username update via 'PUT /api/v1/user/username' and profile persistence.
6. Email update workflow including same-email rejection (400), collision (409), and token re-issuance.
7. Refresh token rotation and session renewal via '/api/v1/refresh'.
8. Hard account deletion via 'DELETE /api/v1/delete' and immediate token invalidation (401).
"""

import pytest
from tests.conftest import generate_random_base64


def test_user_registration_success(client):
    email = "register_test@synclo.app"
    auth_key = generate_random_base64(32)
    device_id = "device_test_01"
    enc_mk = generate_random_base64(32)
    salt = generate_random_base64(32)

    payload = {
        "email": email,
        "username": "tester",
        "auth_key": auth_key,
        "device_id": device_id,
        "device_name": "Test Laptop",
        "os": "Windows 11",
        "encrypted_master_key": enc_mk,
        "salt": salt,
        "kdf_version": 1,
    }

    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["username"] == "tester"

    # Verify login returns TokenWithE2EE containing kdf_version and keys
    login_res = client.post("/api/v1/login", json={
        "email": email,
        "auth_key": auth_key,
        "device_id": "device_test_02",
        "device_name": "Phone",
        "os": "Android",
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["kdf_version"] == 1
    assert "encrypted_master_key" in login_data
    assert "salt" in login_data


def test_duplicate_user_registration_fails(client, user_factory):
    u = user_factory(email="dup@synclo.app")

    # Try registering again with the same email
    payload = {
        "email": "dup@synclo.app",
        "username": "another_name",
        "auth_key": generate_random_base64(32),
        "device_id": "different_device",
        "device_name": "Test",
        "os": "Linux",
        "encrypted_master_key": generate_random_base64(32),
        "salt": generate_random_base64(32),
        "kdf_version": 1,
    }
    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 409


def test_get_salt(client, user_factory):
    email = "salt_test@synclo.app"
    user_factory(email=email)

    res = client.get("/api/v1/auth/salt", params={"email": email})
    assert res.status_code == 200
    data = res.json()
    assert "salt" in data
    assert data["kdf_version"] == 1


def test_get_user_profile(client, auth_user):
    res = client.get("/api/v1/user", headers=auth_user["headers"])
    assert res.status_code == 200
    profile = res.json()
    assert profile["email"] == auth_user["email"]
    assert profile["username"] == auth_user["username"]
    assert "user_id" in profile
    assert profile["kdf_version"] == 1


def test_update_username(client, auth_user):
    res = client.put(
        "/api/v1/user/username",
        json={"username": "new_awesome_name"},
        headers=auth_user["headers"],
    )
    assert res.status_code == 200
    assert res.json()["username"] == "new_awesome_name"

    # Verify profile reflects the new username
    res_prof = client.get("/api/v1/user", headers=auth_user["headers"])
    assert res_prof.json()["username"] == "new_awesome_name"


def test_update_email_flow(client, user_factory):
    user_a = user_factory(email="user_a@synclo.app")
    user_b = user_factory(email="user_b@synclo.app")

    # 1. Same email rejection -> 400
    res_same = client.put(
        "/api/v1/user/email",
        json={"email": "user_a@synclo.app"},
        headers=user_a["headers"],
    )
    assert res_same.status_code == 400

    # 2. Existing User B email conflict -> 409
    res_conflict = client.put(
        "/api/v1/user/email",
        json={"email": "user_b@synclo.app"},
        headers=user_a["headers"],
    )
    assert res_conflict.status_code == 409

    # 3. Successful email update -> 200
    new_email = "user_a_new@synclo.app"
    res_update = client.put(
        "/api/v1/user/email",
        json={"email": new_email},
        headers=user_a["headers"],
    )
    assert res_update.status_code == 200
    data = res_update.json()
    assert data["email"] == new_email
    new_token = data["access_token"]

    # 4. Profile check with new token
    res_prof = client.get("/api/v1/user", headers={"Authorization": f"Bearer {new_token}"})
    assert res_prof.status_code == 200
    assert res_prof.json()["email"] == new_email


def test_login_with_invalid_credentials_fails(client, user_factory):
    email = "neg_auth_test@synclo.app"
    u = user_factory(email=email)

    # 1. Invalid auth_key (wrong password key) -> 401
    wrong_key = generate_random_base64(32)
    res_wrong_pw = client.post("/api/v1/login", json={
        "email": email,
        "auth_key": wrong_key,
        "device_id": "test_dev",
    })
    assert res_wrong_pw.status_code == 401

    # 2. Non-existent email -> 401
    res_no_user = client.post("/api/v1/login", json={
        "email": "non_existent_user_999@synclo.app",
        "auth_key": u["auth_key"],
        "device_id": "test_dev",
    })
    assert res_no_user.status_code == 401

    # 3. Malformed base64 auth_key -> 401
    res_bad_b64 = client.post("/api/v1/login", json={
        "email": email,
        "auth_key": "not-valid-base64!",
        "device_id": "test_dev",
    })
    assert res_bad_b64.status_code == 401


def test_refresh_token_flow(client, auth_user):
    refresh_tok = auth_user["refresh_token"]
    res = client.post("/api/v1/refresh", json={"refresh_token": refresh_tok})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    new_access_token = data["access_token"]

    # Verify new access token works
    res_prof = client.get("/api/v1/user", headers={"Authorization": f"Bearer {new_access_token}"})
    assert res_prof.status_code == 200


def test_refresh_token_reuse_revokes_entire_token_family(client, auth_user):
    r1 = auth_user["refresh_token"]

    # 1. Normal refresh: R1 -> R2 (R1 becomes revoked)
    res1 = client.post("/api/v1/refresh", json={"refresh_token": r1})
    assert res1.status_code == 200
    r2 = res1.json()["refresh_token"]

    # 2. Attacker / replay attempt with old R1 -> should detect reuse and revoke entire family
    res_reuse = client.post("/api/v1/refresh", json={"refresh_token": r1})
    assert res_reuse.status_code == 401
    assert "Refresh token reused" in res_reuse.json()["detail"]

    # 3. Legitimate client tries to use R2 -> should also fail because family was terminated
    res_victim = client.post("/api/v1/refresh", json={"refresh_token": r2})
    assert res_victim.status_code == 401


def test_account_deletion(client, auth_user):
    res = client.delete("/api/v1/delete", headers=auth_user["headers"])
    assert res.status_code == 200

    # Authenticated routes should now fail as user is deleted
    res_prof = client.get("/api/v1/user", headers=auth_user["headers"])
    assert res_prof.status_code == 401
