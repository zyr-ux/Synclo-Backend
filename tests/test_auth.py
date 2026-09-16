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

import base64
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.database.engine import run_in_write_transaction
from app.database.models import BlacklistedToken, Device, RefreshToken, User
from app.endpoints.auth_endpoints import decode_and_validate_blob
from app.services.auth import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    create_refresh_token,
    get_auth_context,
)
from app.utilities.helpers import hash_refresh_token
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
    import jwt
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
    from app.database.engine import Base
    from app.database.models import User, Device
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
        success_count = statuses.count(200)
        fail_count = statuses.count(401)
        # At most one should succeed; token reuse / race condition yields 401
        assert success_count + fail_count == 2
        assert success_count <= 1
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
    from app.database.schemas import AuthContext

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
    from app.database.models import RefreshToken
    from app.services.auth import hash_refresh_token

    user = user_factory()
    refresh_token = user["refresh_token"]
    hashed_token = hash_refresh_token(refresh_token)

    # 1. Verify token exists and is active
    token_record = db_session.scalars(
        select(RefreshToken).where(RefreshToken.token == hashed_token)
    ).first()
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
    token_record_after = db_session.scalars(
        select(RefreshToken).where(RefreshToken.token == hashed_token)
    ).first()
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
        if (
            route.path.startswith("/api/v1")
            and route.methods
            and route.methods.intersection({"POST", "PUT", "PATCH", "DELETE"})
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


# =====================================================================
# Auth Primitives & Edge Cases
# =====================================================================


def test_create_access_token_default_expiry_and_epoch():
    data = {"sub": "user@synclo.app", "device_id": "dev-1"}
    token = create_access_token(data)

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "user@synclo.app"
    assert payload["device_id"] == "dev-1"
    assert payload["epoch"] == 1

    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = exp - now
    # Default is 15 minutes; allow slight clock leeway
    assert 13 * 60 <= delta.total_seconds() <= 16 * 60


def test_create_access_token_custom_expiry_and_explicit_epoch():
    custom_delta = timedelta(hours=2)
    data = {"sub": "user@synclo.app", "device_id": "dev-2", "epoch": 7}
    token = create_access_token(data, expires_delta=custom_delta)

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["epoch"] == 7
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = exp - now
    assert 118 * 60 <= delta.total_seconds() <= 122 * 60


def test_create_refresh_token_stores_hash_and_auto_uuid(db_session):
    user_id = "test-user-id"
    device_id = "test-dev-id"

    plain_token = create_refresh_token(db_session, user_id=user_id, device_id=device_id)

    assert isinstance(plain_token, str)
    assert len(plain_token) > 32

    # Find the inserted token in the session
    rt_records = [
        item for item in db_session.new if isinstance(item, RefreshToken)
    ]
    assert len(rt_records) == 1
    rt = rt_records[0]

    # Invariant: Plaintext token must NEVER be stored in the DB (Zero-Knowledge rule)
    assert rt.token != plain_token
    assert rt.token == hash_refresh_token(plain_token)
    assert rt.user_id == user_id
    assert rt.device_id == device_id
    assert rt.is_revoked is False

    # Auto-generated token_id should be a valid UUID
    UUID(rt.token_id, version=4)


def test_create_refresh_token_with_explicit_token_id(db_session):
    explicit_id = "family-rotation-id-123"
    create_refresh_token(
        db_session,
        user_id="user-xyz",
        device_id="dev-xyz",
        token_id=explicit_id,
    )

    rt_records = [
        item for item in db_session.new if isinstance(item, RefreshToken)
    ]
    assert any(rt.token_id == explicit_id for rt in rt_records)


def _setup_user_and_device(db_session, email="alice@synclo.app", epoch=1):
    def mutate():
        user = User(
            user_id="user-auth-ctx-" + email,
            email=email,
            username="alice",
            session_epoch=epoch,
            auth_key_hash="dummy_auth_key_hash",
            salt=b"salt_16_bytes_00",
            encrypted_master_key=b"emk_32_bytes_0000000000000000000",
            kdf_version=1,
            recovery_wrapped_master_key=b"rec_32_bytes_0000000000000000000",
            recovery_key_verifier="verifier_hex_string_32_bytes",
        )
        db_session.add(user)
        device = Device(
            device_id="dev-auth-ctx",
            user_id="user-auth-ctx-" + email,
            device_name="Laptop",
            os="Linux",
        )
        db_session.add(device)

    run_in_write_transaction(db_session, mutate)


def test_get_auth_context_valid(db_session):
    _setup_user_and_device(db_session, email="valid_auth@synclo.app", epoch=1)
    token = create_access_token({"sub": "valid_auth@synclo.app", "device_id": "dev-auth-ctx", "epoch": 1})

    ctx = get_auth_context(token=token, db=db_session)
    assert ctx.user.email == "valid_auth@synclo.app"
    assert ctx.device_id == "dev-auth-ctx"


def test_get_auth_context_missing_claims(db_session):
    # Missing sub
    tok_no_sub = jwt.encode({"device_id": "dev-1", "epoch": 1, "exp": 9999999999}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc1:
        get_auth_context(token=tok_no_sub, db=db_session)
    assert exc1.value.status_code == 401

    # Missing exp
    tok_no_exp = jwt.encode({"sub": "user@synclo.app", "device_id": "dev-1", "epoch": 1}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc2:
        get_auth_context(token=tok_no_exp, db=db_session)
    assert exc2.value.status_code == 401

    # Missing epoch
    tok_no_epoch = jwt.encode({"sub": "user@synclo.app", "device_id": "dev-1", "exp": 9999999999}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc3:
        get_auth_context(token=tok_no_epoch, db=db_session)
    assert exc3.value.status_code == 401


def test_get_auth_context_blacklisted_token(db_session):
    token = create_access_token({"sub": "user@synclo.app", "device_id": "dev-1", "epoch": 1})

    def mutate():
        db_session.add(
            BlacklistedToken(
                token=token,
                expiry=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )

    run_in_write_transaction(db_session, mutate)

    with pytest.raises(HTTPException) as exc:
        get_auth_context(token=token, db=db_session)
    assert exc.value.status_code == 401
    assert "Token has been revoked" in exc.value.detail


def test_get_auth_context_user_not_found(db_session):
    token = create_access_token({"sub": "nonexistent@synclo.app", "device_id": "dev-1", "epoch": 1})
    with pytest.raises(HTTPException) as exc:
        get_auth_context(token=token, db=db_session)
    assert exc.value.status_code == 401


def test_get_auth_context_epoch_mismatch(db_session):
    _setup_user_and_device(db_session, email="epoch_test@synclo.app", epoch=2)
    # Token issued under epoch 1, but user is currently on epoch 2
    stale_token = create_access_token({"sub": "epoch_test@synclo.app", "device_id": "dev-auth-ctx", "epoch": 1})

    with pytest.raises(HTTPException) as exc:
        get_auth_context(token=stale_token, db=db_session)
    assert exc.value.status_code == 401
    assert "Session revoked, please re-authenticate" in exc.value.detail


def test_get_auth_context_unauthorized_device(db_session):
    _setup_user_and_device(db_session, email="device_test@synclo.app", epoch=1)
    # Token issued for a device that does not belong to the user
    foreign_dev_token = create_access_token(
        {"sub": "device_test@synclo.app", "device_id": "non_existent_device", "epoch": 1}
    )

    with pytest.raises(HTTPException) as exc:
        get_auth_context(token=foreign_dev_token, db=db_session)
    assert exc.value.status_code == 403
    assert "Unauthorized device" in exc.value.detail


def test_decode_and_validate_blob_boundaries():
    # Exactly 16 bytes
    b16 = base64.b64encode(b"0" * 16).decode("utf-8")
    res16 = decode_and_validate_blob(b16, min_len=16, max_len=32, field_name="boundary_field")
    assert len(res16) == 16

    # Exactly 32 bytes
    b32 = base64.b64encode(b"0" * 32).decode("utf-8")
    res32 = decode_and_validate_blob(b32, min_len=16, max_len=32, field_name="boundary_field")
    assert len(res32) == 32


def test_decode_and_validate_blob_out_of_bounds():
    # Below min (15 bytes when min is 16)
    b15 = base64.b64encode(b"0" * 15).decode("utf-8")
    with pytest.raises(HTTPException) as exc_low:
        decode_and_validate_blob(b15, min_len=16, max_len=32, field_name="low_field")
    assert exc_low.value.status_code == 400
    assert "low_field length out of bounds" in exc_low.value.detail

    # Above max (33 bytes when max is 32)
    b33 = base64.b64encode(b"0" * 33).decode("utf-8")
    with pytest.raises(HTTPException) as exc_high:
        decode_and_validate_blob(b33, min_len=16, max_len=32, field_name="high_field")
    assert exc_high.value.status_code == 400
    assert "high_field length out of bounds" in exc_high.value.detail


def test_decode_and_validate_blob_invalid_base64():
    with pytest.raises(HTTPException) as exc:
        decode_and_validate_blob("not-valid-base64!@@#", min_len=1, max_len=64, field_name="salt_field")
    assert exc.value.status_code == 400
    assert "Invalid base64 encoding for salt_field" in exc.value.detail


def test_password_change_rejects_undersized_new_auth_key(client, user_factory):
    user = user_factory()
    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(15),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 400
    assert "auth_key length out of bounds" in res.json()["detail"]


def test_password_change_rejects_undersized_new_salt(client, user_factory):
    user = user_factory()
    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(15),
        "new_kdf_version": 1,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 400
    assert "salt length out of bounds" in res.json()["detail"]


def test_password_change_rejects_oversized_encrypted_master_key(client, user_factory):
    user = user_factory()
    # Undersized encrypted master key (< MIN_MK_LEN=16) triggers endpoint runtime validation
    payload_low = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(15),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }
    res_low = client.post("/api/v1/password/change", json=payload_low, headers=user["headers"])
    assert res_low.status_code == 400
    assert "encrypted_master_key length out of bounds" in res_low.json()["detail"]

    # Oversized string exceeding schema max_length triggers Pydantic 422
    payload_high = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": "A" * 2049,
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 1,
    }
    res_high = client.post("/api/v1/password/change", json=payload_high, headers=user["headers"])
    assert res_high.status_code == 422


def test_password_change_rejects_unsupported_kdf_version(client, user_factory):
    user = user_factory()
    change_payload = {
        "old_auth_key": user["auth_key"],
        "new_auth_key": generate_random_base64(32),
        "new_encrypted_master_key": generate_random_base64(32),
        "new_salt": generate_random_base64(32),
        "new_kdf_version": 99,
    }
    res = client.post("/api/v1/password/change", json=change_payload, headers=user["headers"])
    assert res.status_code == 400
    assert "Unsupported kdf_version" in res.json()["detail"]


def test_login_rejects_device_id_too_short(client, user_factory):
    user = user_factory()
    res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ab",
        },
    )
    assert res.status_code == 400
    assert "device_id length out of bounds" in res.json()["detail"]


def test_login_rejects_device_id_too_long(client, user_factory):
    user = user_factory()
    res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "x" * 200,
        },
    )
    assert res.status_code == 422


def test_register_rejects_device_id_boundaries(client):
    # Length 2 passes Pydantic (min_length=1) but fails endpoint runtime check (MIN_DEVICE_ID_LEN=3)
    res_short = client.post(
        "/api/v1/register",
        json={
            "email": "dev_bounds_short@example.com",
            "auth_key": generate_random_base64(32),
            "device_id": "ab",
            "encrypted_master_key": generate_random_base64(32),
            "salt": generate_random_base64(32),
            "recovery_wrapped_master_key": generate_random_base64(32),
            "recovery_key_verifier": generate_random_base64(32),
        },
    )
    assert res_short.status_code == 400
    assert "device_id length out of bounds" in res_short.json()["detail"]

    # Length > 128 fails Pydantic schema validation
    res_long = client.post(
        "/api/v1/register",
        json={
            "email": "dev_bounds_long@example.com",
            "auth_key": generate_random_base64(32),
            "device_id": "x" * 200,
            "encrypted_master_key": generate_random_base64(32),
            "salt": generate_random_base64(32),
            "recovery_wrapped_master_key": generate_random_base64(32),
            "recovery_key_verifier": generate_random_base64(32),
        },
    )
    assert res_long.status_code == 422


def test_get_salt_guard_is_unreachable_due_to_not_null_constraint(db_session):
    from sqlalchemy.exc import IntegrityError

    invalid_user = User(
        email="null_salt_verify@example.com",
        auth_key_hash="hash",
        encrypted_master_key=b"enc_mk",
        salt=None,
        recovery_wrapped_master_key=b"rec_mk",
        recovery_key_verifier="verifier",
    )
    db_session.add(invalid_user)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()
