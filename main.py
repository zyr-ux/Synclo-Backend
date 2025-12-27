import asyncio
import traceback
from datetime import datetime, timedelta
from secrets import token_urlsafe
from typing import List
from fastapi import FastAPI, Depends, HTTPException, Body, Request, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from redis.asyncio import Redis
from Crypto.Random import get_random_bytes
from jose import JWTError, jwt
from database import SessionLocal
from models import User, Device, Clipboard, EncryptionKey, RefreshToken, BlacklistedToken
from schemas import Token, UserRegisterWithDevice, UserLoginWithDevice, DeviceRegister, DeviceOut, ClipboardIn, ClipboardOut, ClipboardOutList, SessionInfo, RefreshTokenRequest # Import new schema
from auth import hash_password, verify_password, create_access_token, get_current_user, get_user_from_token_ws, SECRET_KEY, ALGORITHM
from crypto_utils import encrypt_clipboard, decrypt_clipboard, hash_refresh_token
from connection_manager import ConnectionManager
from utils import cleanup_expired_refresh_tokens, cleanup_old_clipboard_entries, cleanup_expired_blacklisted_tokens # Ensure this is imported
from logging_config import logger
from config import Settings
from uuid import uuid4

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = Settings.REFRESH_TOKEN_EXPIRE_DAYS

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
    
    # Start background cleanup task
    asyncio.create_task(periodic_cleanup())


@app.on_event("shutdown")
async def shutdown():
    await manager.stop_listener()
    redis = getattr(app.state, "redis", None)
    if redis:
        try:
            await redis.close()
        except Exception as e:
            logger.warning(f"Redis close failed: {e}")

async def periodic_cleanup():
    while True:
        try:
            # Run cleanup in a thread to avoid blocking event loop
            def run_cleanup():
                db = SessionLocal()
                try:
                    cleanup_expired_blacklisted_tokens(db)
                finally:
                    db.close()

            await asyncio.to_thread(run_cleanup)
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

@app.post("/register", response_model=Token,dependencies=[Depends(RateLimiter(times=3, seconds=60))])
def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
    # Check if email already registered
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if device_id is already in use by another user
    existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
    if existing_device:
        raise HTTPException(status_code=409, detail="Device ID already in use. Please use a unique device ID.")
    
    # Create new user
    new_user = User(email=user.email, hashed_password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create device for the new user
    new_device = Device(
        device_id=user.device_id,
        device_name=user.device_name,
        user_id=new_user.id
    )
    db.add(new_device)
    db.commit()

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
    from uuid import uuid4
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

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer"
    }

# Login route
@app.post("/login", response_model=Token, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cleanup_expired_refresh_tokens(db)

    device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user.id).first()
    if not device:
        # Auto-register new devices for seamless multi-device support
        device = Device(
            device_id=user.device_id,
            device_name=user.device_name or "Dev Device",
            user_id=db_user.id
        )
        db.add(device)
        db.commit()
        db.refresh(device)

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
        "token_type": "bearer"
    }

@app.post("/devices/register", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def register_device(
    device: DeviceRegister,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
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
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device

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
    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()
    if not key_entry:
        from Crypto.Random import get_random_bytes
        key_entry = EncryptionKey(user_id=current_user.id, key=get_random_bytes(32))
        db.add(key_entry)
        db.commit()
        db.refresh(key_entry)

    encrypted_data, nonce = encrypt_clipboard(data.text, key_entry.key)

    new_entry = Clipboard(
        uid=str(uuid4()), # Generate UUID
        user_id=current_user.id,
        encrypted_data=encrypted_data,
        nonce=nonce
    )
    db.add(new_entry)
    db.commit()

    return {"status": "clipboard synced", "id": new_entry.uid}

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
    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()

    if not entry or not key_entry:
        raise HTTPException(status_code=404, detail="No clipboard found")

    try:
        text = decrypt_clipboard(entry.encrypted_data, key_entry.key)
        return {
                "id": entry.uid, # Return UUID
                "text": text,
                "timestamp": entry.timestamp
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

@app.get("/clipboard/all", response_model=ClipboardOutList, dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_clipboard_history(
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cleanup_old_clipboard_entries(current_user.id, db)

    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()
    if not key_entry:
        raise HTTPException(status_code=404, detail="Encryption key not found")

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

    decrypted = []
    for entry in entries:
        try:
            text = decrypt_clipboard(entry.encrypted_data, key_entry.key)
            decrypted.append({
                "id": entry.uid, # Return UUID
                "text": text,
                "timestamp": entry.timestamp
            })
        except Exception:
            continue  # skip corrupted entries

    return {"history": decrypted}

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

        db.add(BlacklistedToken(token=access_token, expiry=datetime.utcfromtimestamp(exp)))

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    hashed_refresh = hash_refresh_token(request.refresh_token) # Access via .refresh_token
    db.query(RefreshToken).filter(RefreshToken.token == hashed_refresh).delete()

    db.commit()
    return {"message": "Logged out successfully"}

@app.post("/refresh", response_model=Token, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def refresh_token(
    request: RefreshTokenRequest, # Use Pydantic model instead of Body(..., embed=True)
    db: Session = Depends(get_db)
):
    hashed_input = hash_refresh_token(request.refresh_token) # Access via .refresh_token

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

    # Delete user's encryption key
    db.query(EncryptionKey).filter_by(user_id=current_user.id).delete()

    # Delete all refresh tokens
    db.query(RefreshToken).filter_by(user_id=current_user.id).delete()

    # Delete user record
    db.query(User).filter_by(id=current_user.id).delete()

    db.commit()

    # Disconnect all the websockets for this user
    await manager.disconnect_user(current_user.id)

    return {"message": "Your account and all associated data have been deleted."}

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
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await manager.connect(user.id, device_id, websocket)
    
    try:
        while True:
            # Expiry check
            if datetime.utcnow().timestamp() > exp:
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
                except Exception as e:
                    logger.warning(f"WebSocket ping/pong failed: {e}")
                    await websocket.close(code=4002)
                    break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            text = data.get("text")
            if not text:
                continue

            # Run blocking DB operations in a separate thread
            def save_clipboard_entry():
                session = SessionLocal()
                try:
                    key_entry = session.query(EncryptionKey).filter_by(user_id=user.id).first()
                    if not key_entry:
                        key_entry = EncryptionKey(user_id=user.id, key=get_random_bytes(32))
                        session.add(key_entry)
                        session.commit()
                        session.refresh(key_entry)

                    encrypted_data, nonce = encrypt_clipboard(text, key_entry.key)
                    new_entry = Clipboard(
                        uid=str(uuid4()), # Generate UUID
                        user_id=user.id,
                        encrypted_data=encrypted_data,
                        nonce=nonce,
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
                    "id": new_entry.uid, # Broadcast UUID
                    "text": text,
                    "timestamp": new_entry.timestamp.isoformat()
                },
                exclude_device=device_id
            )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        logger.error(traceback.format_exc())
        await websocket.close(code=1011) # Internal Error
    finally:
        manager.disconnect(user.id, device_id)


@app.get("/sessions", response_model=List[SessionInfo], dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_active_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id).all()
    return [
        {
            "device_id": session.device_id,
            "expiry": session.expiry
        }
        for session in sessions
    ]

@app.delete("/sessions/{device_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def revoke_session(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    deleted = db.query(RefreshToken).filter_by(user_id=current_user.id, device_id=device_id).delete()
    db.commit()
    if deleted:
        return {"message": "Session revoked"}
    raise HTTPException(status_code=404, detail="Session not found")