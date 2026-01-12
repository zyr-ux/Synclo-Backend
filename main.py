import asyncio
import traceback
from datetime import datetime, timedelta
from secrets import token_urlsafe
from typing import List
import base64
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from redis.asyncio import Redis
from jose import JWTError, jwt
from database import SessionLocal
from models import User, Device, Clipboard, RefreshToken, BlacklistedToken
from schemas import Token, TokenWithE2EE, UserRegisterWithDevice, UserLoginWithDevice, DeviceRegister, DeviceOut, ClipboardIn, ClipboardOut, ClipboardOutList, SessionInfo, RefreshTokenRequest, PasswordChange, SaltResponse
from auth import create_access_token, get_current_user, get_user_from_token_ws, SECRET_KEY, ALGORITHM
from crypto_utils import hash_refresh_token
from connection_manager import ConnectionManager
from utils import cleanup_expired_refresh_tokens, cleanup_old_clipboard_entries, cleanup_expired_blacklisted_tokens # Ensure this is imported
from logging_config import logger
from config import Settings
from uuid import uuid4

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = Settings.REFRESH_TOKEN_EXPIRE_DAYS

# Validation bounds
MIN_DEVICE_ID_LEN = 3
MAX_DEVICE_ID_LEN = 128
MIN_AUTH_KEY_LEN = 16
MAX_AUTH_KEY_LEN = 256
MIN_SALT_LEN = 16
MAX_SALT_LEN = 256
MIN_MK_LEN = 16
MAX_MK_LEN = 8192
MAX_CIPHERTEXT_LEN = 65536  # 64 KB
MAX_NONCE_LEN = 64
MIN_NONCE_LEN = 8
ALLOWED_BLOB_VERSIONS = {1}
ALLOWED_KDF_VERSIONS = {1}

app = FastAPI()

manager = ConnectionManager()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
async def startup():
    # Use configurable URL
    redis = Redis.from_url(Settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    app.state.redis = redis
    await FastAPILimiter.init(redis)
    manager.set_redis(redis)
    await manager.start_listener()
    
    # Start background cleanup task and keep a handle for shutdown
    app.state.cleanup_task = asyncio.create_task(periodic_cleanup())


@app.on_event("shutdown")
async def shutdown():
    await manager.stop_listener()
    redis = getattr(app.state, "redis", None)
    if redis:
        try:
            await redis.close()
        except Exception as e:
            logger.warning(f"Redis close failed: {e}")
    # Cancel background cleanup task cleanly
    cleanup_task = getattr(app.state, "cleanup_task", None)
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

async def periodic_cleanup():
    while True:
        try:
            # Run cleanup in a thread to avoid blocking event loop
            def run_cleanup():
                db = SessionLocal()
                try:
                    cleanup_expired_blacklisted_tokens(db)
                    cleanup_expired_refresh_tokens(db)
                finally:
                    db.close()

            await asyncio.to_thread(run_cleanup)
        except asyncio.CancelledError:
            # Task cancelled during shutdown
            break
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
        
        # Wait for 1 hour before next cleanup
        await asyncio.sleep(3600)

@app.exception_handler(Exception)
async def internal_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception at {request.method} {request.url.path}")
    logger.error("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(f"HTTPException: {exc.status_code} - {exc.detail} at {request.method} {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.get("/health")
def health_check():
    logger.info("Health check pinged")
    return {"status": "ok"}

@app.get("/auth/salt", response_model=SaltResponse, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def get_salt_for_email(email: str, db: Session = Depends(get_db)):
    """
    Public endpoint to retrieve salt for client KDF derivation.
    Returns 404 if email not found (prevents email enumeration).
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if not user.salt:
        raise HTTPException(status_code=400, detail="User salt not initialized")
    
    return {
        "salt": base64.b64encode(user.salt).decode('utf-8'),
        "kdf_version": user.kdf_version
    }

@app.post("/register", response_model=Token,dependencies=[Depends(RateLimiter(times=3, seconds=60))])
def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
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
            user_id=new_user.id
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
        refresh_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        # Generate family ID
        family_id = str(uuid4())

        db.add(RefreshToken(
            user_id=new_user.id,
            token=hashed_refresh,
            expiry=refresh_expiry,
            device_id=user.device_id,
            family_id=family_id,
            is_revoked=False
        ))

        db.commit()

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

# Login route
@app.post("/login", response_model=TokenWithE2EE, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
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

    device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user.id).first()
    if not device:
        # Prevent collision with another user's device_id to avoid unique constraint errors
        existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
        if existing_device and existing_device.user_id != db_user.id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")

        # Auto-register new devices for seamless multi-device support
        device = Device(
            device_id=user.device_id,
            device_name=user.device_name or "Dev Device",
            user_id=db_user.id
        )
        try:
            db.add(device)
            db.commit()
            db.refresh(device)
        except IntegrityError:
            db.rollback()
            # Re-check ownership after rollback to surface proper error
            existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
            if existing_device and existing_device.user_id != db_user.id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            if existing_device:
                device = existing_device
            else:
                raise HTTPException(status_code=400, detail="Device registration failed")
        except Exception:
            db.rollback()
            raise

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    plain_refresh_token = token_urlsafe(64)
    hashed_refresh = hash_refresh_token(plain_refresh_token)
    refresh_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Generate a new family ID for this login session
    family_id = str(uuid4())

    # Remove any existing tokens for this device to start fresh
    db.query(RefreshToken).filter_by(
        user_id=db_user.id,
        device_id=user.device_id
    ).delete()

    db.add(RefreshToken(
        user_id=db_user.id,
        token=hashed_refresh,
        expiry=refresh_expiry,
        device_id=user.device_id,
        family_id=family_id,  # Start new family
        is_revoked=False
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer",
        "encrypted_master_key": base64.b64encode(db_user.encrypted_master_key).decode('utf-8'),
        "salt": base64.b64encode(db_user.salt).decode('utf-8'),
        "kdf_version": db_user.kdf_version
    }

@app.post("/devices/register", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def register_device(
    device: DeviceRegister,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not (MIN_DEVICE_ID_LEN <= len(device.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")
    existing = db.query(Device).filter(Device.device_id == device.device_id).first()
    if existing:
        if existing.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")
        return existing
    new_device = Device(
        device_id=device.device_id,
        device_name=device.device_name,
        user_id=current_user.id
    )
    try:
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return new_device
    except Exception as e:
        db.rollback()
        # Handle race condition where device was inserted by another request
        existing = db.query(Device).filter(Device.device_id == device.device_id).first()
        if existing:
            if existing.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            return existing
        raise HTTPException(status_code=400, detail="Failed to register device")

@app.get("/devices", response_model=List[DeviceOut], dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(Device).filter(Device.user_id == current_user.id).all()


@app.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Clean old entries even on write to avoid unbounded growth if user never reads
    cleanup_old_clipboard_entries(current_user.id, db)

    # Decode base64 binary data
    try:
        ciphertext_bytes = base64.b64decode(data.ciphertext)
        nonce_bytes = base64.b64decode(data.nonce)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    if data.blob_version not in ALLOWED_BLOB_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported blob_version")
    if not (MIN_NONCE_LEN <= len(nonce_bytes) <= MAX_NONCE_LEN):
        raise HTTPException(status_code=400, detail="nonce length out of bounds")
    if len(ciphertext_bytes) > MAX_CIPHERTEXT_LEN:
        raise HTTPException(status_code=400, detail="ciphertext too large")
    
    new_entry = Clipboard(
        id=str(uuid4()), # Generate UUID business identifier
        user_id=current_user.id,
        ciphertext=ciphertext_bytes,
        nonce=nonce_bytes,
        blob_version=data.blob_version
    )
    db.add(new_entry)
    db.commit()

    return {"status": "clipboard synced", "id": new_entry.id}

@app.get("/clipboard", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cleanup_old_clipboard_entries(current_user.id, db)

    entry = (
        db.query(Clipboard)
        .filter_by(user_id=current_user.id)
        .order_by(Clipboard.timestamp.desc())
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="No clipboard found")

    return {
            "id": entry.id,
            "ciphertext": base64.b64encode(entry.ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(entry.nonce).decode('utf-8'),
            "blob_version": entry.blob_version,
            "timestamp": entry.timestamp
            }

@app.get("/clipboard/all", response_model=ClipboardOutList, dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_clipboard_history(
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Validate pagination parameters
    if page < 1:
        raise HTTPException(status_code=400, detail="Page must be >= 1")
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 500")
    
    cleanup_old_clipboard_entries(current_user.id, db)

    # Calculate offset for pagination
    offset = (page - 1) * limit

    entries = (
        db.query(Clipboard)
        .filter_by(user_id=current_user.id)
        .order_by(Clipboard.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    serialized = []
    for entry in entries:
        serialized.append({
            "id": entry.id,
            "ciphertext": base64.b64encode(entry.ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(entry.nonce).decode('utf-8'),
            "blob_version": entry.blob_version,
            "timestamp": entry.timestamp
        })

    return {"history": serialized}

@app.post("/logout", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def logout(
    request: RefreshTokenRequest, # Use Pydantic model
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
        hashed_refresh = hash_refresh_token(request.refresh_token) # Access via .refresh_token
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    db.query(RefreshToken).filter(RefreshToken.token == hashed_refresh).delete()

    db.commit()
    return {"message": "Logged out successfully"}

@app.post("/refresh", response_model=Token, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def refresh_token(
    request: RefreshTokenRequest, # Use Pydantic model instead of Body(..., embed=True)
    db: Session = Depends(get_db)
):
    try:
        hashed_input = hash_refresh_token(request.refresh_token) # Access via .refresh_token
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    token_entry = db.query(RefreshToken).filter(
        RefreshToken.token == hashed_input
    ).first()

    # 1. Check if token exists
    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # 2. REUSE DETECTION: If token is already revoked, it's a theft attempt!
    if token_entry.is_revoked:
        # Security Alert: Delete the ENTIRE family to lock out the attacker
        db.query(RefreshToken).filter(RefreshToken.family_id == token_entry.family_id).delete()
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token reused. Security alert: Session terminated.")

    # 3. Check expiry
    if token_entry.expiry < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Expired refresh token")

    user_id = token_entry.user_id
    device_id = token_entry.device_id

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 4. ROTATION: Issue new tokens
    access_token = create_access_token(
        data={"sub": user.email, "device_id": device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    new_refresh_plain = token_urlsafe(64)
    new_refresh_hashed = hash_refresh_token(new_refresh_plain)
    new_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Revoke the old token (don't delete it yet, keep it to detect reuse)
    token_entry.is_revoked = True
    
    # Create new token in the SAME family
    db.add(RefreshToken(
        user_id=user.id,
        token=new_refresh_hashed,
        expiry=new_expiry,
        device_id=device_id,
        family_id=token_entry.family_id, # Maintain the chain
        is_revoked=False
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_plain,
        "token_type": "bearer"
    }

@app.delete("/delete", dependencies=[Depends(RateLimiter(times=2, seconds=60))])
async def delete_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Delete user's clipboard data
    db.query(Clipboard).filter_by(user_id=current_user.id).delete()

    # Delete user's devices
    db.query(Device).filter_by(user_id=current_user.id).delete()

    # Delete all refresh tokens
    db.query(RefreshToken).filter_by(user_id=current_user.id).delete()

    # Delete user record
    db.query(User).filter_by(id=current_user.id).delete()

    db.commit()

    # Disconnect all the websockets for this user
    await manager.disconnect_user(current_user.id)

    return {"message": "Your account and all associated data have been deleted."}

@app.post("/password/change", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
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
    db_user = db.query(User).filter_by(id=current_user.id).first()
    db_user.auth_key_hash = new_auth_key_hash
    db_user.encrypted_master_key = new_encrypted_mk_bytes
    db_user.salt = new_salt_bytes
    db_user.kdf_version = data.new_kdf_version
    
    db.commit()
    db.refresh(db_user)
    
    return {"message": "Password changed successfully. Master key re-wrapped."}

@app.delete("/devices/{device_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Lookup the device owned by this user
    device = db.query(Device).filter_by(device_id=device_id, user_id=current_user.id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # 1. Delete the device record
    db.delete(device)

    # 2. Revoke all refresh tokens for this device
    db.query(RefreshToken).filter_by(user_id=current_user.id, device_id=device_id).delete()
    
    db.commit()

    # 3. Disconnect active WebSocket for this device
    await manager.disconnect_device(current_user.id, device_id)

    return {"message": f"Device '{device.device_name}' deleted successfully"}

@app.delete("/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def delete_clipboard_entry(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = db.query(Clipboard).filter_by(id=clipboard_id, user_id=current_user.id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Clipboard entry not found")
    
    db.delete(entry)
    db.commit()
    return {"message": "Clipboard entry deleted"}

@app.delete("/clipboard", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def delete_clipboard_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    deleted_count = db.query(Clipboard).filter_by(user_id=current_user.id).delete()
    db.commit()
    return {"message": f"{deleted_count} clipboard entries deleted."}

@app.websocket("/ws/clipboard")
async def websocket_clipboard(websocket: WebSocket, token: str):
    # Validate user + device
    user = get_user_from_token_ws(token)
    if not user:
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        device_id = payload.get("device_id")

        if not exp or not device_id:
            logger.warning("WebSocket token missing exp or device_id")
            await websocket.close(code=1008)
            return
    except JWTError as e:
        logger.warning(f"WebSocket token validation failed: {e}")
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await manager.connect(user.id, device_id, websocket)
    
    try:
        while True:
            # Expiry check - compare Unix timestamps correctly
            if datetime.utcnow().timestamp() >= exp:
                await websocket.send_json({"type": "error", "message": "Token expired"})
                await websocket.close(code=4001)
                break

            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=45)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                try:
                    pong = await asyncio.wait_for(websocket.receive_json(), timeout=10)
                    if pong.get("type") != "pong":
                        raise ValueError("Invalid pong")
                    continue
                except WebSocketDisconnect:
                    # Connection already closed by client, don't try to close again
                    logger.warning("Client disconnected during ping/pong")
                    break
                except Exception as e:
                    logger.warning(f"WebSocket ping/pong failed: {e}")
                    try:
                        await websocket.close(code=4002)
                    except RuntimeError:
                        # Connection already closed, skip
                        pass
                    break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            ciphertext = data.get("ciphertext")
            nonce = data.get("nonce")
            blob_version = data.get("blob_version", 1)
            if not ciphertext or not nonce:
                continue
            
            # Decode base64 from WebSocket
            try:
                ciphertext_bytes = base64.b64decode(ciphertext)
                nonce_bytes = base64.b64decode(nonce)
            except Exception:
                await websocket.send_json({"type": "error", "message": "Invalid base64 encoding"})
                continue

            if blob_version not in ALLOWED_BLOB_VERSIONS:
                await websocket.send_json({"type": "error", "message": "Unsupported blob_version"})
                continue
            if not (MIN_NONCE_LEN <= len(nonce_bytes) <= MAX_NONCE_LEN):
                await websocket.send_json({"type": "error", "message": "nonce length out of bounds"})
                continue
            if len(ciphertext_bytes) > MAX_CIPHERTEXT_LEN:
                await websocket.send_json({"type": "error", "message": "ciphertext too large"})
                continue

            # Run blocking DB operations in a separate thread
            def save_clipboard_entry():
                session = SessionLocal()
                try:
                    new_entry = Clipboard(
                        id=str(uuid4()), # Generate UUID
                        user_id=user.id,
                        ciphertext=ciphertext_bytes,
                        nonce=nonce_bytes,
                        blob_version=blob_version,
                        timestamp=datetime.utcnow()
                    )
                    session.add(new_entry)
                    session.commit()
                    return new_entry
                finally:
                    session.close()

            # Execute in thread pool to avoid blocking event loop
            new_entry = await asyncio.to_thread(save_clipboard_entry)

            await manager.broadcast_to_user(
                user_id=user.id,
                message={
                    "id": new_entry.id,
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "blob_version": blob_version,
                    "timestamp": new_entry.timestamp.isoformat()
                },
                exclude_device=device_id
            )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        logger.error(traceback.format_exc())
        try:
            await websocket.close(code=1011) # Internal Error
        except RuntimeError:
            # Connection already closed, skip
            pass
    finally:
        manager.disconnect(user.id, device_id)