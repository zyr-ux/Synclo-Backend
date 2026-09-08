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
        "recovery_wrapped_master_key": generate_random_base64(32),
        "recovery_key_verifier": generate_random_base64(32),
    }

    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["username"] == "tester"

    # Verify login returns TokenWithE2EE containing kdf_version and keys
    login_res = client.post(
        "/api/v1/login",
        json={
            "email": email,
            "auth_key": auth_key,
            "device_id": "device_test_02",
            "device_name": "Phone",
            "os": "Android",
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["kdf_version"] == 1
    assert "encrypted_master_key" in login_data
    assert "salt" in login_data


def test_device_id_can_be_shared_by_different_users(client, user_factory):
    shared_device_id = "shared_hardware_device"
    first_user = user_factory(email="first_shared@synclo.app", device_id=shared_device_id)
    second_user = user_factory(email="second_shared@synclo.app", device_id=shared_device_id)

    assert first_user["access_token"]
    assert second_user["access_token"]


def test_duplicate_user_registration_fails(client, user_factory):
    user_factory(email="dup@synclo.app")

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
        "recovery_wrapped_master_key": generate_random_base64(32),
        "recovery_key_verifier": generate_random_base64(32),
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
    user_factory(email="user_b@synclo.app")

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
    res_wrong_pw = client.post(
        "/api/v1/login",
        json={
            "email": email,
            "auth_key": wrong_key,
            "device_id": "test_dev",
        },
    )
    assert res_wrong_pw.status_code == 401

    # 2. Non-existent email -> 401
    res_no_user = client.post(
        "/api/v1/login",
        json={
            "email": "non_existent_user_999@synclo.app",
            "auth_key": u["auth_key"],
            "device_id": "test_dev",
        },
    )
    assert res_no_user.status_code == 401

    # 3. Malformed base64 auth_key -> 401
    res_bad_b64 = client.post(
        "/api/v1/login",
        json={
            "email": email,
            "auth_key": "not-valid-base64!",
            "device_id": "test_dev",
        },
    )
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


def test_password_change_increments_epoch_and_invalidates_all_tokens(client, user_factory):
    user = user_factory()

    # Log in as Device 2
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_epoch_2",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]
    headers_dev2 = {"Authorization": f"Bearer {token_dev2}"}

    # Verify Device 2 can access /api/v1/user
    res_before = client.get("/api/v1/user", headers=headers_dev2)
    assert res_before.status_code == 200

    # Device 1 changes password
    new_auth_key = generate_random_base64(32)
    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": new_auth_key,
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
    }
    res_change = client.post(
        "/api/v1/password/change", json=change_payload, headers=user["headers"]
    )
    assert res_change.status_code == 200

    # Device 2's token must be rejected because its epoch is stale
    res_after = client.get("/api/v1/user", headers=headers_dev2)
    assert res_after.status_code == 401
    assert "session revoked" in res_after.json()["detail"].lower()

    # Device 2's WebSocket attempt with old token must be closed with code 4004
    with client.websocket_connect("/ws/v1/sync", headers=headers_dev2) as ws:
        frame = ws.receive_json()
        assert frame["type"] == "session_invalidated"


def test_token_without_epoch_claim_rejected(client, auth_user):
    from datetime import datetime, timezone
    from jose import jwt
    from app.services.auth import SECRET_KEY, ALGORITHM

    # Create a token without epoch
    payload = {
        "sub": auth_user["email"],
        "device_id": auth_user["device_id"],
        "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
    }
    raw_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    res = client.get("/api/v1/user", headers={"Authorization": f"Bearer {raw_token}"})
    assert res.status_code == 401


def test_password_change_revokes_all_device_refresh_tokens(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_pw_revoke_2",
        },
    )
    assert dev2_res.status_code == 200
    dev2_refresh_token = dev2_res.json()["refresh_token"]

    # Device 1 changes password
    new_auth_key = generate_random_base64(32)
    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": new_auth_key,
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
        "new_recovery_wrapped_master_key": generate_random_base64(32),
        "new_recovery_key_verifier": generate_random_base64(32),
    }
    res_change = client.post(
        "/api/v1/password/change", json=change_payload, headers=user["headers"]
    )
    assert res_change.status_code == 200

    # Device 2 attempts refresh with old refresh token -> must be rejected
    res_refresh = client.post("/api/v1/refresh", json={"refresh_token": dev2_refresh_token})
    assert res_refresh.status_code == 401
    assert "session terminated" in res_refresh.json()["detail"].lower()


def test_email_change_revokes_other_device_refresh_tokens(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "dev_email_revoke_2",
        },
    )
    assert dev2_res.status_code == 200

    res_change = client.put(
        "/api/v1/user/email",
        json={"email": f"changed_{user['email']}"},
        headers=user["headers"],
    )
    assert res_change.status_code == 200

    res_refresh = client.post(
        "/api/v1/refresh",
        json={"refresh_token": dev2_res.json()["refresh_token"]},
    )
    assert res_refresh.status_code == 401


def test_concurrent_refresh_token_race(client, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    from app.models.models import User, Device
    from app.services.auth import create_refresh_token, get_db
    from app.main import app

    db_path = tmp_path / "race_test.db"
    file_engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 15})
    Base.metadata.create_all(bind=file_engine)
    FileSession = sessionmaker(bind=file_engine)

    # Set up user and initial token
    init_db = FileSession()
    user = User(
        user_id="user_race",
        email="race@test.com",
        auth_key_hash="hash",
        encrypted_master_key=b"emk",
        salt=b"salt",
        recovery_wrapped_master_key=b"rwmk",
        recovery_key_verifier="rkv",
    )
    init_db.add(user)
    device = Device(device_id="dev_race", device_name="Race Device", user_id="user_race")
    init_db.add(device)
    init_db.commit()

    raw_token = create_refresh_token(init_db, user_id="user_race", device_id="dev_race")
    init_db.commit()
    init_db.close()

    def get_test_db():
        db = FileSession()
        try:
            yield db
        finally:
            db.close()

    orig_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = get_test_db

    try:

        def do_refresh():
            return client.post("/api/v1/refresh", json={"refresh_token": raw_token})

        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(do_refresh)
            f2 = executor.submit(do_refresh)
            res1 = f1.result()
            res2 = f2.result()

        statuses = [res1.status_code, res2.status_code]
        assert 200 in statuses
        assert 401 in statuses
    finally:
        if orig_override:
            app.dependency_overrides[get_db] = orig_override
        else:
            app.dependency_overrides.pop(get_db, None)
        file_engine.dispose()


def test_logout_with_another_users_refresh_token_does_not_affect_victim(client, user_factory):
    user_a = user_factory()
    user_b = user_factory()

    # User A tries to log out passing User B's refresh token
    res = client.post(
        "/api/v1/logout", json={"refresh_token": user_b["refresh_token"]}, headers=user_a["headers"]
    )
    assert res.status_code == 200

    # Verify User B's refresh token remains active and can be used
    res_b_refresh = client.post("/api/v1/refresh", json={"refresh_token": user_b["refresh_token"]})
    assert res_b_refresh.status_code == 200
    assert "access_token" in res_b_refresh.json()


def test_get_auth_context_structure_and_no_monkey_patching(client, auth_user, db_session):
    from app.services.auth import get_auth_context
    from app.schemas.schemas import AuthContext

    token = auth_user["access_token"]
    expected_device_id = auth_user["device_id"]
    expected_email = auth_user["email"]

    auth_ctx = get_auth_context(token=token, db=db_session)
    assert isinstance(auth_ctx, AuthContext)
    assert auth_ctx.user.email == expected_email
    assert auth_ctx.device_id == expected_device_id

    # Invariant: No monkey-patching of current_device_id on SQLAlchemy User instance
    assert (
        not hasattr(auth_ctx.user, "current_device_id")
        or getattr(auth_ctx.user, "current_device_id", None) is None
    )


def test_logout_revokes_token_and_detects_reuse(client, user_factory, db_session):
    from app.models.models import RefreshToken
    from app.services.auth import hash_refresh_token

    user = user_factory()
    refresh_token = user["refresh_token"]
    hashed_token = hash_refresh_token(refresh_token)

    # 1. Verify token exists and is active
    token_record = db_session.query(RefreshToken).filter_by(token=hashed_token).first()
    assert token_record is not None
    assert token_record.is_revoked is False

    # 2. Call logout
    res_logout = client.post(
        "/api/v1/logout", json={"refresh_token": refresh_token}, headers=user["headers"]
    )
    assert res_logout.status_code == 200
    assert res_logout.json()["message"] == "Logged out successfully"

    # 3. Verify record was marked is_revoked=True instead of being deleted
    db_session.expire_all()
    token_record_after = db_session.query(RefreshToken).filter_by(token=hashed_token).first()
    assert token_record_after is not None
    assert token_record_after.is_revoked is True

    # 4. Attempt to reuse the logged-out refresh token -> triggers reuse detection
    res_reuse = client.post("/api/v1/refresh", json={"refresh_token": refresh_token})
    assert res_reuse.status_code == 401
    assert "Refresh token reused" in res_reuse.json()["detail"]


def test_logging_redacts_emails():
    import logging
    from app.core.logging_config import RedactingFilter

    redactor = RedactingFilter()

    # Formatted string message
    record1 = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="WebSocket connection attempted for user: secret_user@example.com",
        args=(),
        exc_info=None,
    )
    redactor.filter(record1)
    assert "secret_user@example.com" not in record1.msg
    assert "[REDACTED]" in record1.msg

    # Argument-interpolated message
    record2 = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="Authentication failure for %s",
        args=("another_user@domain.co.uk",),
        exc_info=None,
    )
    redactor.filter(record2)
    assert "another_user@domain.co.uk" not in record2.msg
    assert "[REDACTED]" in record2.msg

    # Direct helper test
    from app.utilities.helpers import RedactingFilter

    assert (
        RedactingFilter.redact("Contact us at support@synclo.internal for help")
        == "Contact us at [REDACTED] for help"
    )
    assert RedactingFilter.redact(123) == 123


def test_schema_field_bounds_validation(client, auth_headers):
    # 1. DeviceRename: device_name max_length=128 (129 chars should fail)
    res_rename = client.patch(
        "/api/v1/devices/dev-1", json={"device_name": "A" * 129}, headers=auth_headers
    )
    assert res_rename.status_code == 422

    # 2. PasswordChange: old_auth_key max_length=512 (513 chars should fail)
    res_pwd = client.post(
        "/api/v1/password/change",
        json={
            "old_auth_key": "B" * 513,
            "new_auth_key": "valid_new_key",
            "new_encrypted_master_key": "valid_emk",
            "new_salt": "valid_salt",
            "new_kdf_version": 1,
        },
        headers=auth_headers,
    )
    assert res_pwd.status_code == 422

    # 3. PasswordChange: new_kdf_version out of bounds (> 100 should fail)
    res_kdf = client.post(
        "/api/v1/password/change",
        json={
            "old_auth_key": "valid_old_key",
            "new_auth_key": "valid_new_key",
            "new_encrypted_master_key": "valid_emk",
            "new_salt": "valid_salt",
            "new_kdf_version": 101,
        },
        headers=auth_headers,
    )
    assert res_kdf.status_code == 422

    # 4. AccountRecoveryRequest: recovery_key_verifier max_length=512 (513 chars should fail)
    res_recover = client.post(
        "/api/v1/auth/recover",
        json={
            "email": "recover_bound@test.com",
            "recovery_key_verifier": "C" * 513,
            "new_auth_key": "new_key",
            "new_encrypted_master_key": "new_emk",
            "new_salt": "new_salt",
            "new_recovery_wrapped_master_key": "new_rwmk",
            "new_recovery_key_verifier": "new_rkv",
            "device_id": "new_dev",
        },
    )
    assert res_recover.status_code == 422


def test_all_mutating_endpoints_enforce_rate_limiting():
    from fastapi.routing import APIRoute
    from app.main import app

    unprotected_routes = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        # Check all sensitive write endpoints under /api/v1
        if route.path.startswith("/api/v1") and route.methods.intersection(
            {"POST", "PUT", "PATCH", "DELETE"}
        ):
            has_limiter = any(
                "RateLimiter" in getattr(dep.dependency, "__name__", "")
                or "RateLimiter" in type(dep.dependency).__name__
                or "RateLimiter" in str(dep.dependency)
                for dep in route.dependencies
            )
            if not has_limiter:
                unprotected_routes.append(f"{route.methods} {route.path}")

    assert not unprotected_routes, (
        f"Sensitive endpoints missing RateLimiter dependency: {unprotected_routes}"
    )
