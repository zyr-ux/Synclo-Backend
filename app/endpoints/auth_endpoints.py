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
    UsernameUpdate,
    UserResponse,
    EmailUpdate,
    EmailUpdateResponse,
)
from app.services.auth import (
    create_access_token,
    create_refresh_token,
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
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if user.salt is None:
        raise HTTPException(status_code=400, detail="User salt not initialized")
    
    return {
        "salt": base64.b64encode(user.salt).decode('utf-8'),
        "kdf_version": user.kdf_version
    }


@router.post("/register", response_model=Token, dependencies=[Depends(RateLimiter(times=3, seconds=60))])
async def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")

    if user.kdf_version not in ALLOWED_KDF_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported kdf_version")

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    
    existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
    if existing_device:
        raise HTTPException(status_code=409, detail="Device ID already in use. Please use a unique device ID.")
    
    try:
        encrypted_mk_bytes = base64.b64decode(user.encrypted_master_key)
        salt_bytes = base64.b64decode(user.salt)
        auth_key_bytes = base64.b64decode(user.auth_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for key material")

    if not (MIN_AUTH_KEY_LEN <= len(auth_key_bytes) <= MAX_AUTH_KEY_LEN):
        raise HTTPException(status_code=400, detail="auth_key length out of bounds")
    if not (MIN_SALT_LEN <= len(salt_bytes) <= MAX_SALT_LEN):
        raise HTTPException(status_code=400, detail="salt length out of bounds")
    if not (MIN_MK_LEN <= len(encrypted_mk_bytes) <= MAX_MK_LEN):
        raise HTTPException(status_code=400, detail="encrypted_master_key length out of bounds")
    
    auth_key_hash = bcrypt.hashpw(auth_key_bytes, bcrypt.gensalt()).decode('utf-8')

    try:
        new_user = User(
            user_id=str(uuid4()),
            email=user.email,
            username=user.username,
            auth_key_hash=auth_key_hash,
            encrypted_master_key=encrypted_mk_bytes,
            salt=salt_bytes,
            kdf_version=user.kdf_version
        )

        db.add(new_user)
        db.flush()

        new_device = Device(
            device_id=user.device_id,
            device_name=user.device_name,
            os=user.os,
            user_id=new_user.user_id
        )
        db.add(new_device)
        db.flush()

        access_token = create_access_token(
            data={"sub": new_user.email, "device_id": user.device_id},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        plain_refresh_token = create_refresh_token(db, user_id=new_user.user_id, device_id=user.device_id)
        db.commit()

        await manager.broadcast_to_user(
            user_id=new_user.user_id,
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
        "token_type": "bearer",
        "username": new_user.username
    }


@router.post("/login", response_model=TokenWithE2EE, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not (MIN_DEVICE_ID_LEN <= len(user.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")
    
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

    db_user_id: str = db_user.user_id

    device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user_id).first()
    if not device:
        existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
        if existing_device and existing_device.user_id != db_user_id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")

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
            existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
            if existing_device and existing_device.user_id != db_user_id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            if existing_device:
                device = existing_device
            else:
                raise HTTPException(status_code=400, detail="Device registration failed")

    if user.os and device.os != user.os:
        device.os = user.os
        db.commit()
        db.refresh(device)
        await manager.broadcast_to_user(
            user_id=db_user_id,
            message={
                "type": "device_updated",
                "device": {
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "os": device.os
                }
            },
            exclude_device=user.device_id
        )

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    db.query(RefreshToken).filter_by(
        user_id=db_user_id,
        device_id=user.device_id
    ).delete()

    plain_refresh_token = create_refresh_token(db, user_id=db_user_id, device_id=user.device_id)
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

        if not db.query(BlacklistedToken).filter(BlacklistedToken.token == access_token).first():
            db.add(BlacklistedToken(token=access_token, expiry=datetime.fromtimestamp(exp, tz=timezone.utc)))
        db.commit()

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

    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if token_entry.is_revoked:
        db.query(RefreshToken).filter(RefreshToken.token_id == token_entry.token_id).delete()
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token reused. Security alert: Session terminated.")

    expiry_utc = token_entry.expiry.replace(tzinfo=timezone.utc) if token_entry.expiry.tzinfo is None else token_entry.expiry

    if expiry_utc < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Expired refresh token")

    user_id: str = token_entry.user_id
    device_id: str = token_entry.device_id

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    token_entry.is_revoked = True

    new_refresh_plain = create_refresh_token(
        db,
        user_id=user_id,
        device_id=device_id,
        token_id=token_entry.token_id
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_plain,
        "token_type": "bearer",
        "username": user.username
    }


@router.delete("/delete", dependencies=[Depends(RateLimiter(times=2, seconds=60))])
async def delete_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    db.query(Clipboard).filter_by(user_id=user_id).delete()
    db.query(Device).filter_by(user_id=user_id).delete()
    db.query(RefreshToken).filter_by(user_id=user_id).delete()
    db.query(User).filter_by(user_id=user_id).delete()

    db.commit()

    await manager.disconnect_user(user_id)

    return {"message": "Your account and all associated data have been deleted."}


@router.post("/password/change", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        old_auth_key_bytes = base64.b64decode(data.old_auth_key)
        if not bcrypt.checkpw(old_auth_key_bytes, current_user.auth_key_hash.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Incorrect authentication key")
    except Exception as e:
        logger.error(f"Auth key verification failed: {e}")
        raise HTTPException(status_code=401, detail="Incorrect authentication key")
    
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
    
    new_auth_key_hash = bcrypt.hashpw(new_auth_key_bytes, bcrypt.gensalt()).decode('utf-8')
    
    current_user.auth_key_hash = new_auth_key_hash
    current_user.encrypted_master_key = new_encrypted_mk_bytes
    current_user.salt = new_salt_bytes
    current_user.kdf_version = data.new_kdf_version

    db.commit()
    db.refresh(current_user)
    
    return {"message": "Password changed successfully. Master key re-wrapped."}


@router.put("/user/username", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def update_username(
    data: UsernameUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device_id = getattr(current_user, "current_device_id", None)

    current_user.username = data.username
    db.commit()
    db.refresh(current_user)

    await manager.broadcast_to_user(
        user_id=current_user.user_id,
        message={
            "type": "username_updated",
            "username": data.username
        },
        exclude_device=device_id
    )
    
    return {"message": "Username updated successfully", "username": data.username}


@router.put("/user/email", response_model=EmailUpdateResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def update_email(
    data: EmailUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device_id = getattr(current_user, "current_device_id", None)
    if not device_id or not (MIN_DEVICE_ID_LEN <= len(device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="Invalid or missing device_id in token")

    if current_user.email == data.email:
        raise HTTPException(status_code=400, detail="New email cannot be the same as current email")

    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    current_user.email = data.email
    try:
        db.commit()
        db.refresh(current_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")

    access_token = create_access_token(
        data={"sub": current_user.email, "device_id": device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    db.query(RefreshToken).filter_by(
        user_id=current_user.user_id,
        device_id=device_id
    ).delete()

    plain_refresh_token = create_refresh_token(db, user_id=current_user.user_id, device_id=device_id)
    db.commit()

    await manager.broadcast_to_user(
        user_id=current_user.user_id,
        message={
            "type": "email_updated",
            "email": data.email
        },
        exclude_device=device_id
    )

    return {
        "message": "Email updated successfully",
        "email": data.email,
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer"
    }


@router.get("/user", response_model=UserResponse, dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_user_profile(current_user: User = Depends(get_current_user)):
    return current_user
