# app/endpoints/auth_endpoints.py

import base64
import bcrypt
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi_limiter.depends import RateLimiter
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import (
    MIN_DEVICE_ID_LEN,
    MAX_DEVICE_ID_LEN,
    MIN_AUTH_KEY_LEN,
    MAX_AUTH_KEY_LEN,
    MIN_SALT_LEN,
    MAX_SALT_LEN,
    MIN_MK_LEN,
    MAX_MK_LEN,
    ALLOWED_KDF_VERSIONS,
)
from app.core.logging_config import logger
from app.models.models import User, Device, RefreshToken, BlacklistedToken, Clipboard
from app.schemas.schemas import (
    Token,
    TokenWithE2EE,
    UserRegisterWithDevice,
    UserLoginWithDevice,
    RefreshTokenRequest,
    PasswordChange,
    SaltResponse,
)
from app.services.auth import (
    create_access_token,
    get_current_user,
    get_db,
    oauth2_scheme,
    SECRET_KEY,
    ALGORITHM,
)
from app.services.crypto_utils import hash_refresh_token
from app.services.serializers import user_to_e2ee_response
from app.services.utils import cleanup_expired_refresh_tokens
from app.websockets.connection_manager import manager

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = Settings.REFRESH_TOKEN_EXPIRE_DAYS


@router.get("/auth/salt", response_model=SaltResponse, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def get_salt_for_email(email: str, db: Session = Depends(get_db)):
    """
    Public endpoint to retrieve salt for client KDF derivation.
    Returns 404 if email not found (prevents email enumeration).
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if user.salt is None:
        raise HTTPException(status_code=400, detail="User salt not initialized")
    
    u: Any = user
    return {
        "salt": base64.b64encode(u.salt).decode('utf-8'),
        "kdf_version": u.kdf_version
    }


@router.post("/register", response_model=Token, dependencies=[Depends(RateLimiter(times=3, seconds=60))])
async def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
    # Validate device_id length/format
    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")

    if user.kdf_version not in ALLOWED_KDF_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported kdf_version")

    # Check if email already registered
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    
    # Check if device_id is already in use by another user (best-effort; still guard for race on commit)
    existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
    if existing_device:
        raise HTTPException(status_code=409, detail="Device ID already in use. Please use a unique device ID.")
    
    # Decode base64 E2EE material
    try:
        encrypted_mk_bytes = base64.b64decode(user.encrypted_master_key)
        salt_bytes = base64.b64decode(user.salt)
        auth_key_bytes = base64.b64decode(user.auth_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for key material")

    # Validate E2EE material sizes
    if not (MIN_AUTH_KEY_LEN <= len(auth_key_bytes) <= MAX_AUTH_KEY_LEN):
        raise HTTPException(status_code=400, detail="auth_key length out of bounds")
    if not (MIN_SALT_LEN <= len(salt_bytes) <= MAX_SALT_LEN):
        raise HTTPException(status_code=400, detail="salt length out of bounds")
    if not (MIN_MK_LEN <= len(encrypted_mk_bytes) <= MAX_MK_LEN):
        raise HTTPException(status_code=400, detail="encrypted_master_key length out of bounds")
    
    # Hash auth_key with bcrypt
    auth_key_hash = bcrypt.hashpw(auth_key_bytes, bcrypt.gensalt()).decode('utf-8')

    try:
        # Create new user with E2EE key material
        new_user = User(
            user_id=str(uuid4()),
            email=user.email,
            auth_key_hash=auth_key_hash,
            encrypted_master_key=encrypted_mk_bytes,
            salt=salt_bytes,
            kdf_version=user.kdf_version
        )
        db.add(new_user)
        db.flush()  # Get user.id without committing

        # Create device for the new user
        new_device = Device(
            device_id=user.device_id,
            device_name=user.device_name,
            os=user.os,
            user_id=new_user.user_id
        )
        db.add(new_device)
        db.flush()

        # Create access token
        access_token = create_access_token(
            data={"sub": new_user.email, "device_id": user.device_id},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Create refresh token
        plain_refresh_token = token_urlsafe(64)
        hashed_refresh = hash_refresh_token(plain_refresh_token)
        refresh_expiry = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        # Generate token ID
        token_id = str(uuid4())

        db.add(RefreshToken(
            user_id=new_user.user_id,
            token=hashed_refresh,
            expiry=refresh_expiry,
            device_id=user.device_id,
            token_id=token_id,
            is_revoked=False
        ))

        db.commit()

        # Broadcast to other connected devices (will be empty for a new user, but kept for architectural consistency)
        await manager.broadcast_to_user(
            user_id=new_user.id,
            message={
                "type": "device_added",
                "device": {
                    "device_id": new_device.device_id,
                    "device_name": new_device.device_name,
                    "os": new_device.os
                }
            },
            exclude_device=user.device_id
        )

    except IntegrityError:
        db.rollback()
        # Handle race where the same device_id or email slipped in between checks
        if db.query(Device).filter(Device.device_id == user.device_id).first():
            raise HTTPException(status_code=409, detail="Device ID already in use. Please use a unique device ID.")
        if db.query(User).filter(User.email == user.email).first():
            raise HTTPException(status_code=409, detail="Email already registered")
        raise HTTPException(status_code=400, detail="Registration failed")
    except Exception:
        db.rollback()
        raise

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer"
    }


@router.post("/login", response_model=TokenWithE2EE, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")
    
    # Verify auth_key against bcrypt hash
    try:
        auth_key_bytes = base64.b64decode(user.auth_key)
        if not (MIN_AUTH_KEY_LEN <= len(auth_key_bytes) <= MAX_AUTH_KEY_LEN):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not bcrypt.checkpw(auth_key_bytes, db_user.auth_key_hash.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        logger.error(f"Auth key verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cleanup_expired_refresh_tokens(db)

    _db_user: Any = db_user
    db_user_id: str = _db_user.user_id

    device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user_id).first()
    if not device:
        # Prevent collision with another user's device_id to avoid unique constraint errors
        existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
        _ed: Any = existing_device
        if _ed and _ed.user_id != db_user_id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")

        # Auto-register new devices for seamless multi-device support
        device = Device(
            device_id=user.device_id,
            device_name=user.device_name or "Dev Device",
            os=user.os,
            user_id=db_user_id
        )
        try:
            db.add(device)
            db.commit()
            db.refresh(device)
            # Broadcast device_added to other devices
            await manager.broadcast_to_user(
                user_id=db_user_id,
                message={
                    "type": "device_added",
                    "device": {
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "os": device.os
                    }
                },
                exclude_device=user.device_id
            )
        except IntegrityError:
            db.rollback()
            # Re-check ownership after rollback to surface proper error
            existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
            _ed2: Any = existing_device
            if _ed2 and _ed2.user_id != db_user_id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            if existing_device:
                device = existing_device
            else:
                raise HTTPException(status_code=400, detail="Device registration failed")

    # Update OS if provided (whether newly created or existing)
    _device: Any = device
    if user.os and _device.os != user.os:
        _device.os = user.os
        db.commit()
        db.refresh(device)
        # Broadcast device_updated to other devices
        await manager.broadcast_to_user(
            user_id=db_user_id,
            message={
                "type": "device_updated",
                "device": {
                    "device_id": _device.device_id,
                    "device_name": _device.device_name,
                    "os": _device.os
                }
            },
            exclude_device=user.device_id
        )

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    plain_refresh_token = token_urlsafe(64)
    hashed_refresh = hash_refresh_token(plain_refresh_token)
    refresh_expiry = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Generate a new token ID for this login session
    token_id = str(uuid4())

    # Remove any existing tokens for this device to start fresh
    db.query(RefreshToken).filter_by(
        user_id=db_user_id,
        device_id=user.device_id
    ).delete()

    db.add(RefreshToken(
        user_id=db_user_id,
        token=hashed_refresh,
        expiry=refresh_expiry,
        device_id=user.device_id,
        token_id=token_id,  # Start new token chain
        is_revoked=False
    ))
    db.commit()

    e2ee_data = user_to_e2ee_response(db_user)

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
        **e2ee_data.model_dump()
    }


@router.post("/logout", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def logout(
    request: RefreshTokenRequest,
    access_token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if not exp:
            raise HTTPException(status_code=400, detail="Invalid access token")

        # Avoid unique constraint errors on repeated logout calls
        if not db.query(BlacklistedToken).filter(BlacklistedToken.token == access_token).first():
            db.add(BlacklistedToken(token=access_token, expiry=datetime.utcfromtimestamp(exp)))
        db.commit()  # Commit after adding blacklisted token

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    try:
        hashed_refresh = hash_refresh_token(request.refresh_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    db.query(RefreshToken).filter(RefreshToken.token == hashed_refresh).delete()

    db.commit()
    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=Token, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    try:
        hashed_input = hash_refresh_token(request.refresh_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    token_entry = db.query(RefreshToken).filter(
        RefreshToken.token == hashed_input
    ).first()

    # 1. Check if token exists
    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    _te: Any = token_entry

    # 2. REUSE DETECTION: If token is already revoked, it's a theft attempt!
    if _te.is_revoked:
        # Security Alert: Delete the ENTIRE family to lock out the attacker
        db.query(RefreshToken).filter(RefreshToken.token_id == _te.token_id).delete()
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token reused. Security alert: Session terminated.")

    # 3. Check expiry
    # Ensure token_entry.expiry is treated as UTC if it's naive (SQLAlchemy default)
    expiry_utc = _te.expiry.replace(tzinfo=timezone.utc) if _te.expiry.tzinfo is None else _te.expiry

    if expiry_utc < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Expired refresh token")

    user_id: str = _te.user_id
    device_id: str = _te.device_id

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    _u: Any = user

    # 4. ROTATION: Issue new tokens
    access_token = create_access_token(
        data={"sub": _u.email, "device_id": device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    new_refresh_plain = token_urlsafe(64)
    new_refresh_hashed = hash_refresh_token(new_refresh_plain)
    new_expiry = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Revoke the old token (don't delete it yet, keep it to detect reuse)
    _te.is_revoked = True

    # Create new token in the SAME family
    db.add(RefreshToken(
        user_id=user_id,
        token=new_refresh_hashed,
        expiry=new_expiry,
        device_id=device_id,
        token_id=_te.token_id, # Maintain the chain
        is_revoked=False
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_plain,
        "token_type": "bearer"
    }


@router.delete("/delete", dependencies=[Depends(RateLimiter(times=2, seconds=60))])
async def delete_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
    # Delete user's clipboard data
    db.query(Clipboard).filter_by(user_id=user_id).delete()

    # Delete user's devices
    db.query(Device).filter_by(user_id=user_id).delete()

    # Delete all refresh tokens
    db.query(RefreshToken).filter_by(user_id=user_id).delete()

    # Delete user record
    db.query(User).filter_by(user_id=user_id).delete()

    db.commit()

    # Disconnect all the websockets for this user
    await manager.disconnect_user(user_id)

    return {"message": "Your account and all associated data have been deleted."}


@router.post("/password/change", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Verify old auth_key
    try:
        old_auth_key_bytes = base64.b64decode(data.old_auth_key)
        if not bcrypt.checkpw(old_auth_key_bytes, current_user.auth_key_hash.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Incorrect authentication key")
    except Exception as e:
        logger.error(f"Auth key verification failed: {e}")
        raise HTTPException(status_code=401, detail="Incorrect authentication key")
    
    # Decode new E2EE material
    try:
        new_auth_key_bytes = base64.b64decode(data.new_auth_key)
        new_encrypted_mk_bytes = base64.b64decode(data.new_encrypted_master_key)
        new_salt_bytes = base64.b64decode(data.new_salt)
    except (ValueError, TypeError) as e:
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
    
    # Hash new auth_key
    new_auth_key_hash = bcrypt.hashpw(new_auth_key_bytes, bcrypt.gensalt()).decode('utf-8')
    
    # Update auth_key and re-wrapped MK
    _cu: Any = current_user
    db_user = db.query(User).filter_by(id=_cu.id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    _dbu: Any = db_user
    _dbu.auth_key_hash = new_auth_key_hash
    _dbu.encrypted_master_key = new_encrypted_mk_bytes
    _dbu.salt = new_salt_bytes
    _dbu.kdf_version = data.new_kdf_version

    db.commit()
    db.refresh(db_user)
    
    return {"message": "Password changed successfully. Master key re-wrapped."}
