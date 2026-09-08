import base64
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi_limiter.depends import RateLimiter
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import (
    MIN_DEVICE_ID_LEN,
    MAX_DEVICE_ID_LEN,
    MIN_DEVICE_NAME_LEN,
    MAX_DEVICE_NAME_LEN,
    MIN_AUTH_KEY_LEN,
    MAX_AUTH_KEY_LEN,
    MIN_SALT_LEN,
    MAX_SALT_LEN,
    MIN_MK_LEN,
    MAX_MK_LEN,
    MIN_RECOVERY_KEY_VERIFIER_LEN,
    MAX_RECOVERY_KEY_VERIFIER_LEN,
    ALLOWED_KDF_VERSIONS,
)
from app.core.logging_config import logger
from app.core.database import run_in_write_transaction
from app.models.models import User, Device, RefreshToken, BlacklistedToken, Clipboard
from app.schemas.schemas import (
    Token,
    TokenWithE2EE,
    UserRegisterWithDevice,
    UserLoginWithDevice,
    RefreshTokenRequest,
    PasswordChange,
    SaltResponse,
    UsernameUpdate,
    UserResponse,
    EmailUpdate,
    EmailUpdateResponse,
    RecoveryMaterialRequest,
    RecoveryMaterialResponse,
    AccountRecoveryRequest,
    RecoveryKeyRotateRequest,
    AuthContext,
)
from app.services.auth import (
    create_access_token,
    create_refresh_token,
    get_auth_context,
    get_db,
    oauth2_scheme,
    SECRET_KEY,
    ALGORITHM,
)
from app.services.serializers import user_to_e2ee_response
from app.utilities.helpers import (
    cleanup_expired_refresh_tokens,
    hash_refresh_token,
    strict_b64decode,
)
from app.websockets.connection_manager import manager


router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = Settings.REFRESH_TOKEN_EXPIRE_DAYS


DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"timing_attack_mitigation_dummy_hash", bcrypt.gensalt()).decode(
    "utf-8"
)


def decode_and_validate_blob(value: str, min_len: int, max_len: int, field_name: str) -> bytes:
    try:
        raw_bytes = strict_b64decode(value, field_name)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid base64 encoding for {field_name}")
    if not (min_len <= len(raw_bytes) <= max_len):
        raise HTTPException(status_code=400, detail=f"{field_name} length out of bounds")
    return raw_bytes


@router.get(
    "/auth/salt",
    response_model=SaltResponse,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
)
def get_salt_for_email(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    if user.salt is None:
        raise HTTPException(status_code=400, detail="User salt not initialized")

    return {"salt": base64.b64encode(user.salt).decode("utf-8"), "kdf_version": user.kdf_version}


@router.post(
    "/auth/recovery-material",
    response_model=RecoveryMaterialResponse,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
)
def get_recovery_material(request: RecoveryMaterialRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not user.recovery_wrapped_master_key:
        raise HTTPException(status_code=401, detail="Could not recover account")

    return {
        "recovery_wrapped_master_key": base64.b64encode(user.recovery_wrapped_master_key).decode(
            "utf-8"
        )
    }


@router.post(
    "/auth/recover", response_model=Token, dependencies=[Depends(RateLimiter(times=3, seconds=60))]
)
async def recover_account(data: AccountRecoveryRequest, db: Session = Depends(get_db)):
    if not (MIN_DEVICE_ID_LEN <= len(data.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")

    if data.device_name and not (
        MIN_DEVICE_NAME_LEN <= len(data.device_name) <= MAX_DEVICE_NAME_LEN
    ):
        raise HTTPException(status_code=400, detail="device_name length out of bounds")

    if data.new_kdf_version not in ALLOWED_KDF_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported kdf_version")

    recovery_verifier_bytes = decode_and_validate_blob(
        data.recovery_key_verifier,
        MIN_RECOVERY_KEY_VERIFIER_LEN,
        MAX_RECOVERY_KEY_VERIFIER_LEN,
        "recovery_key_verifier",
    )
    new_auth_key_bytes = decode_and_validate_blob(
        data.new_auth_key, MIN_AUTH_KEY_LEN, MAX_AUTH_KEY_LEN, "new_auth_key"
    )
    new_encrypted_mk_bytes = decode_and_validate_blob(
        data.new_encrypted_master_key, MIN_MK_LEN, MAX_MK_LEN, "new_encrypted_master_key"
    )
    new_salt_bytes = decode_and_validate_blob(data.new_salt, MIN_SALT_LEN, MAX_SALT_LEN, "new_salt")
    new_recovery_wrapped_mk_bytes = decode_and_validate_blob(
        data.new_recovery_wrapped_master_key,
        MIN_MK_LEN,
        MAX_MK_LEN,
        "new_recovery_wrapped_master_key",
    )
    new_recovery_verifier_bytes = decode_and_validate_blob(
        data.new_recovery_key_verifier,
        MIN_RECOVERY_KEY_VERIFIER_LEN,
        MAX_RECOVERY_KEY_VERIFIER_LEN,
        "new_recovery_key_verifier",
    )

    user = db.query(User).filter(User.email == data.email).first()
    if not user or not user.recovery_key_verifier:
        bcrypt.checkpw(recovery_verifier_bytes, DUMMY_BCRYPT_HASH.encode("utf-8"))
        raise HTTPException(status_code=401, detail="Could not recover account")

    if not bcrypt.checkpw(recovery_verifier_bytes, user.recovery_key_verifier.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Could not recover account")

    new_auth_key_hash = bcrypt.hashpw(new_auth_key_bytes, bcrypt.gensalt()).decode("utf-8")
    new_recovery_verifier_hash = bcrypt.hashpw(
        new_recovery_verifier_bytes, bcrypt.gensalt()
    ).decode("utf-8")

    def mutate() -> tuple[Device, str]:
        user.auth_key_hash = new_auth_key_hash
        user.encrypted_master_key = new_encrypted_mk_bytes
        user.salt = new_salt_bytes
        user.kdf_version = data.new_kdf_version
        user.recovery_wrapped_master_key = new_recovery_wrapped_mk_bytes
        user.recovery_key_verifier = new_recovery_verifier_hash
        db.query(RefreshToken).filter(RefreshToken.user_id == user.user_id).update(
            {"is_revoked": True}
        )

        device = db.query(Device).filter_by(device_id=data.device_id, user_id=user.user_id).first()
        if device:
            if data.device_name:
                device.device_name = data.device_name
            if data.os:
                device.os = data.os
            device.last_seen = datetime.now(timezone.utc)
        else:
            device = Device(
                device_id=data.device_id,
                device_name=data.device_name or "Recovered Device",
                os=data.os,
                user_id=user.user_id,
                last_seen=datetime.now(timezone.utc),
            )
            db.add(device)
        user.session_epoch += 1
        db.flush()
        refresh_token = create_refresh_token(db, user_id=user.user_id, device_id=device.device_id)
        return device, refresh_token

    device, plain_refresh_token = run_in_write_transaction(db, mutate)
    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id, "epoch": user.session_epoch},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    await manager.disconnect_user(user.user_id, code=4004)

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
        "username": user.username,
    }


@router.post(
    "/register", response_model=Token, dependencies=[Depends(RateLimiter(times=3, seconds=60))]
)
async def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")

    if user.kdf_version not in ALLOWED_KDF_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported kdf_version")

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    encrypted_mk_bytes = decode_and_validate_blob(
        user.encrypted_master_key, MIN_MK_LEN, MAX_MK_LEN, "encrypted_master_key"
    )
    salt_bytes = decode_and_validate_blob(user.salt, MIN_SALT_LEN, MAX_SALT_LEN, "salt")
    auth_key_bytes = decode_and_validate_blob(
        user.auth_key, MIN_AUTH_KEY_LEN, MAX_AUTH_KEY_LEN, "auth_key"
    )
    recovery_wrapped_mk_bytes = decode_and_validate_blob(
        user.recovery_wrapped_master_key, MIN_MK_LEN, MAX_MK_LEN, "recovery_wrapped_master_key"
    )
    recovery_verifier_bytes = decode_and_validate_blob(
        user.recovery_key_verifier,
        MIN_RECOVERY_KEY_VERIFIER_LEN,
        MAX_RECOVERY_KEY_VERIFIER_LEN,
        "recovery_key_verifier",
    )

    auth_key_hash = bcrypt.hashpw(auth_key_bytes, bcrypt.gensalt()).decode("utf-8")
    recovery_key_verifier_hash = bcrypt.hashpw(recovery_verifier_bytes, bcrypt.gensalt()).decode(
        "utf-8"
    )

    def mutate() -> tuple[User, Device, str]:
        new_user = User(
            user_id=str(uuid4()),
            email=user.email,
            username=user.username,
            auth_key_hash=auth_key_hash,
            encrypted_master_key=encrypted_mk_bytes,
            salt=salt_bytes,
            kdf_version=user.kdf_version,
            recovery_wrapped_master_key=recovery_wrapped_mk_bytes,
            recovery_key_verifier=recovery_key_verifier_hash,
        )
        db.add(new_user)
        db.flush()

        new_device = Device(
            device_id=user.device_id,
            device_name=user.device_name,
            os=user.os,
            user_id=new_user.user_id,
        )
        db.add(new_device)
        db.flush()

        plain_refresh = create_refresh_token(db, user_id=new_user.user_id, device_id=user.device_id)
        return new_user, new_device, plain_refresh

    try:
        new_user, new_device, plain_refresh_token = run_in_write_transaction(db, mutate)
    except IntegrityError:
        if db.query(User).filter(User.email == user.email).first():
            raise HTTPException(status_code=409, detail="Email already registered")
        raise HTTPException(status_code=400, detail="Registration failed")

    access_token = create_access_token(
        data={"sub": new_user.email, "device_id": user.device_id, "epoch": new_user.session_epoch},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    await manager.broadcast_to_user(
        user_id=new_user.user_id,
        message={
            "type": "device_added",
            "device": {
                "device_id": new_device.device_id,
                "device_name": new_device.device_name,
                "os": new_device.os,
            },
        },
        exclude_device=user.device_id,
    )

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
        "username": new_user.username,
    }


@router.post(
    "/login", response_model=TokenWithE2EE, dependencies=[Depends(RateLimiter(times=5, seconds=60))]
)
async def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")

    try:
        auth_key_bytes = strict_b64decode(user.auth_key, "auth_key")
        if not (MIN_AUTH_KEY_LEN <= len(auth_key_bytes) <= MAX_AUTH_KEY_LEN):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not bcrypt.checkpw(auth_key_bytes, db_user.auth_key_hash.encode("utf-8")):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cleanup_expired_refresh_tokens(db)

    db_user_id: str = db_user.user_id

    def mutate() -> tuple[Device, bool, bool, str]:
        device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user_id).first()
        is_new = False
        os_updated = False
        if not device:
            device = Device(
                device_id=user.device_id,
                device_name=user.device_name or "Dev Device",
                os=user.os,
                user_id=db_user_id,
                last_seen=datetime.now(timezone.utc),
            )
            db.add(device)
            db.flush()
            is_new = True
        else:
            if user.os and device.os != user.os:
                device.os = user.os
                os_updated = True
            device.last_seen = datetime.now(timezone.utc)

        db.query(RefreshToken).filter_by(user_id=db_user_id, device_id=user.device_id).delete()

        plain_refresh = create_refresh_token(db, user_id=db_user_id, device_id=device.device_id)
        return device, is_new, os_updated, plain_refresh

    try:
        device, is_new, os_updated, plain_refresh_token = run_in_write_transaction(db, mutate)
        db.refresh(device)
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Device registration failed")

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id, "epoch": db_user.session_epoch},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    if is_new:
        await manager.broadcast_to_user(
            user_id=db_user_id,
            message={
                "type": "device_added",
                "device": {
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "os": device.os,
                },
            },
            exclude_device=user.device_id,
        )
    elif os_updated:
        await manager.broadcast_to_user(
            user_id=db_user_id,
            message={
                "type": "device_updated",
                "device": {
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "os": device.os,
                },
            },
            exclude_device=user.device_id,
        )

    e2ee_data = user_to_e2ee_response(db_user)

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
        **e2ee_data.model_dump(),
    }


@router.post("/logout", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def logout(
    request: RefreshTokenRequest,
    access_token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        sub = payload.get("sub")
        device_id = payload.get("device_id")
        if not exp or not sub:
            raise HTTPException(status_code=400, detail="Invalid access token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    try:
        hashed_refresh = hash_refresh_token(request.refresh_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    def mutate() -> None:
        if not db.query(BlacklistedToken).filter(BlacklistedToken.token == access_token).first():
            db.add(
                BlacklistedToken(
                    token=access_token, expiry=datetime.fromtimestamp(exp, tz=timezone.utc)
                )
            )

        user = db.query(User).filter(User.email == sub).first()
        if user:
            token_query = db.query(RefreshToken).filter(
                RefreshToken.token == hashed_refresh, RefreshToken.user_id == user.user_id
            )
            if device_id:
                token_query = token_query.filter(RefreshToken.device_id == device_id)
            token_query.update({"is_revoked": True}, synchronize_session=False)

    run_in_write_transaction(db, mutate)

    return {"message": "Logged out successfully"}


@router.post(
    "/refresh", response_model=Token, dependencies=[Depends(RateLimiter(times=10, seconds=60))]
)
def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    try:
        hashed_input = hash_refresh_token(request.refresh_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    def mutate() -> tuple[str, Optional[str], Optional[User], Optional[str]]:
        # Atomic conditional update: only one request can rotate an active token
        rows_updated = (
            db.query(RefreshToken)
            .filter(RefreshToken.token == hashed_input, RefreshToken.is_revoked.is_(False))
            .update({"is_revoked": True}, synchronize_session=False)
        )

        if rows_updated == 0:
            existing = db.query(RefreshToken).filter(RefreshToken.token == hashed_input).first()
            if existing:
                db.query(RefreshToken).filter(RefreshToken.token_id == existing.token_id).update(
                    {"is_revoked": True}, synchronize_session=False
                )
                return "reused", None, None, None
            return "invalid", None, None, None

        token_entry = db.query(RefreshToken).filter(RefreshToken.token == hashed_input).first()
        if not token_entry:
            return "invalid", None, None, None

        expiry_utc = (
            token_entry.expiry.replace(tzinfo=timezone.utc)
            if token_entry.expiry.tzinfo is None
            else token_entry.expiry
        )
        if expiry_utc < datetime.now(timezone.utc):
            return "expired", None, None, None

        user = db.query(User).filter(User.user_id == token_entry.user_id).first()
        if not user:
            return "user_not_found", None, None, None

        new_refresh = create_refresh_token(
            db,
            user_id=token_entry.user_id,
            device_id=token_entry.device_id,
            token_id=token_entry.token_id,
        )
        return "ok", new_refresh, user, token_entry.device_id

    outcome, new_refresh_plain, user, device_id = run_in_write_transaction(db, mutate)

    if outcome == "reused":
        raise HTTPException(
            status_code=401, detail="Refresh token reused. Security alert: Session terminated."
        )
    if outcome == "invalid":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if outcome == "expired":
        raise HTTPException(status_code=401, detail="Expired refresh token")
    if (
        outcome == "user_not_found"
        or user is None
        or device_id is None
        or new_refresh_plain is None
    ):
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device_id, "epoch": user.session_epoch},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_plain,
        "token_type": "bearer",
        "username": user.username,
    }


@router.delete("/delete", dependencies=[Depends(RateLimiter(times=2, seconds=60))])
async def delete_account(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    current_user: User = auth.user
    user_id: str = current_user.user_id

    def mutate() -> None:
        db.query(Clipboard).filter_by(user_id=user_id).delete()
        db.query(Device).filter_by(user_id=user_id).delete()
        db.query(RefreshToken).filter_by(user_id=user_id).delete()
        db.query(User).filter_by(user_id=user_id).delete()

    run_in_write_transaction(db, mutate)

    await manager.disconnect_user(user_id)

    return {"message": "Your account and all associated data have been deleted."}


@router.post("/password/change", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    current_user: User = auth.user
    try:
        old_auth_key_bytes = strict_b64decode(data.old_auth_key, "old_auth_key")
        if not bcrypt.checkpw(old_auth_key_bytes, current_user.auth_key_hash.encode("utf-8")):
            raise HTTPException(status_code=401, detail="Incorrect current password")
    except ValueError:
        raise HTTPException(status_code=401, detail="Incorrect current password")

    try:
        new_auth_key_bytes = strict_b64decode(data.new_auth_key, "new_auth_key")
        new_encrypted_mk_bytes = strict_b64decode(
            data.new_encrypted_master_key, "new_encrypted_master_key"
        )
        new_salt_bytes = strict_b64decode(data.new_salt, "new_salt")
    except ValueError as e:
        logger.error(f"Base64 decoding failed in password change: {e}")
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    if data.new_kdf_version not in ALLOWED_KDF_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported kdf_version")
    if not (MIN_AUTH_KEY_LEN <= len(new_auth_key_bytes) <= MAX_AUTH_KEY_LEN):
        raise HTTPException(status_code=400, detail="auth_key length out of bounds")
    if not (MIN_SALT_LEN <= len(new_salt_bytes) <= MAX_SALT_LEN):
        raise HTTPException(status_code=400, detail="salt length out of bounds")
    if not (MIN_MK_LEN <= len(new_encrypted_mk_bytes) <= MAX_MK_LEN):
        raise HTTPException(status_code=400, detail="encrypted_master_key length out of bounds")

    has_wrapped = data.new_recovery_wrapped_master_key is not None
    has_verifier = data.new_recovery_key_verifier is not None
    if has_wrapped != has_verifier:
        raise HTTPException(
            status_code=400,
            detail="Both new_recovery_wrapped_master_key and new_recovery_key_verifier must be provided together",
        )

    new_recovery_wrapped_bytes = None
    new_recovery_verifier_hash = None
    if has_wrapped and has_verifier:
        new_recovery_wrapped_bytes = decode_and_validate_blob(
            data.new_recovery_wrapped_master_key,
            MIN_MK_LEN,
            MAX_MK_LEN,
            "recovery_wrapped_master_key",
        )
        new_recovery_verifier_bytes = decode_and_validate_blob(
            data.new_recovery_key_verifier,
            MIN_RECOVERY_KEY_VERIFIER_LEN,
            MAX_RECOVERY_KEY_VERIFIER_LEN,
            "recovery_key_verifier",
        )
        new_recovery_verifier_hash = bcrypt.hashpw(
            new_recovery_verifier_bytes, bcrypt.gensalt()
        ).decode("utf-8")

    new_auth_key_hash = bcrypt.hashpw(new_auth_key_bytes, bcrypt.gensalt()).decode("utf-8")

    def mutate() -> None:
        current_user.auth_key_hash = new_auth_key_hash
        current_user.encrypted_master_key = new_encrypted_mk_bytes
        current_user.salt = new_salt_bytes
        current_user.kdf_version = data.new_kdf_version
        if new_recovery_wrapped_bytes is not None:
            current_user.recovery_wrapped_master_key = new_recovery_wrapped_bytes
            current_user.recovery_key_verifier = new_recovery_verifier_hash

        current_user.session_epoch += 1
        db.query(RefreshToken).filter(RefreshToken.user_id == current_user.user_id).update(
            {"is_revoked": True}, synchronize_session=False
        )

    run_in_write_transaction(db, mutate)
    db.refresh(current_user)

    await manager.disconnect_user(current_user.user_id, code=4004)

    return {"message": "Password changed successfully. Master key re-wrapped."}


@router.post("/auth/recovery-key/rotate", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def rotate_recovery_key(
    data: RecoveryKeyRotateRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    current_user: User = auth.user
    new_recovery_wrapped_bytes = decode_and_validate_blob(
        data.new_recovery_wrapped_master_key, MIN_MK_LEN, MAX_MK_LEN, "recovery_wrapped_master_key"
    )
    new_recovery_verifier_bytes = decode_and_validate_blob(
        data.new_recovery_key_verifier,
        MIN_RECOVERY_KEY_VERIFIER_LEN,
        MAX_RECOVERY_KEY_VERIFIER_LEN,
        "recovery_key_verifier",
    )
    new_recovery_verifier_hash = bcrypt.hashpw(
        new_recovery_verifier_bytes, bcrypt.gensalt()
    ).decode("utf-8")

    def mutate() -> None:
        current_user.recovery_wrapped_master_key = new_recovery_wrapped_bytes
        current_user.recovery_key_verifier = new_recovery_verifier_hash

    run_in_write_transaction(db, mutate)
    db.refresh(current_user)

    return {"message": "Recovery key regenerated and updated successfully"}


@router.put("/user/username", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def update_username(
    data: UsernameUpdate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    current_user: User = auth.user
    device_id = auth.device_id

    def mutate() -> None:
        current_user.username = data.username

    run_in_write_transaction(db, mutate)
    db.refresh(current_user)

    await manager.broadcast_to_user(
        user_id=current_user.user_id,
        message={"type": "username_updated", "username": data.username},
        exclude_device=device_id,
    )

    return {"message": "Username updated successfully", "username": data.username}


@router.put(
    "/user/email",
    response_model=EmailUpdateResponse,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
)
async def update_email(
    data: EmailUpdate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    current_user: User = auth.user
    device_id = auth.device_id
    if not device_id or not (MIN_DEVICE_ID_LEN <= len(device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="Invalid or missing device_id in token")

    if current_user.email == data.email:
        raise HTTPException(status_code=400, detail="New email cannot be the same as current email")

    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    def mutate() -> str:
        current_user.email = data.email
        current_user.session_epoch += 1
        db.query(RefreshToken).filter_by(user_id=current_user.user_id).update(
            {"is_revoked": True}, synchronize_session=False
        )
        refresh = create_refresh_token(db, user_id=current_user.user_id, device_id=device_id)
        return refresh

    try:
        plain_refresh_token = run_in_write_transaction(db, mutate)
        db.refresh(current_user)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Email already registered")

    access_token = create_access_token(
        data={
            "sub": current_user.email,
            "device_id": device_id,
            "epoch": current_user.session_epoch,
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    await manager.broadcast_to_user(
        user_id=current_user.user_id,
        message={"type": "email_updated", "email": data.email},
        exclude_device=device_id,
    )
    await manager.disconnect_user(current_user.user_id, code=4004)

    return {
        "message": "Email updated successfully",
        "email": data.email,
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
    }


@router.get(
    "/user", response_model=UserResponse, dependencies=[Depends(RateLimiter(times=20, seconds=60))]
)
def get_user_profile(auth: AuthContext = Depends(get_auth_context)):
    return auth.user
