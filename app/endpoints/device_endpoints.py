# app/endpoints/device_endpoints.py

from datetime import datetime, timezone
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session

from app.core.constants import MIN_DEVICE_ID_LEN, MAX_DEVICE_ID_LEN, MIN_DEVICE_NAME_LEN, MAX_DEVICE_NAME_LEN
from app.models.models import Device, User, RefreshToken
from app.schemas.schemas import DeviceRegister, DeviceRename, DeviceOut
from app.services.auth import get_db, get_current_user
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post("/devices/register", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def register_device(
    device: DeviceRegister,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not (MIN_DEVICE_ID_LEN <= len(device.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")
    _cu: Any = current_user
    current_user_id: str = _cu.user_id
    existing = db.query(Device).filter(Device.device_id == device.device_id).first()
    _ex: Any = existing
    if existing:
        if _ex.user_id != current_user_id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")
        _ex.last_seen = datetime.now(timezone.utc)
        db.commit()
        return DeviceOut(
            device_id=_ex.device_id,
            device_name=_ex.device_name,
            os=_ex.os,
            last_seen=_ex.last_seen,
            is_online=manager.is_device_online(current_user_id, _ex.device_id)
        )
    new_device = Device(
        device_id=device.device_id,
        device_name=device.device_name,
        os=device.os,
        user_id=current_user_id,
        last_seen=datetime.now(timezone.utc)
    )
    try:
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        # Broadcast to other connected devices
        await manager.broadcast_to_user(
            user_id=current_user_id,
            message={
                "type": "device_added",
                "device": {
                    "device_id": new_device.device_id,
                    "device_name": new_device.device_name,
                    "os": new_device.os
                }
            }
        )
        return DeviceOut(
            device_id=new_device.device_id,
            device_name=new_device.device_name,
            os=new_device.os,
            last_seen=new_device.last_seen,
            is_online=manager.is_device_online(current_user_id, new_device.device_id)
        )
    except Exception:
        db.rollback()
        # Handle race condition where device was inserted by another request
        existing = db.query(Device).filter(Device.device_id == device.device_id).first()
        if existing:
            _ex2: Any = existing
            if _ex2.user_id != current_user_id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            return DeviceOut(
                device_id=_ex2.device_id,
                device_name=_ex2.device_name,
                os=_ex2.os,
                last_seen=_ex2.last_seen,
                is_online=manager.is_device_online(current_user_id, _ex2.device_id)
            )
        raise HTTPException(status_code=400, detail="Failed to register device")


@router.get("/devices", response_model=List[DeviceOut], dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).filter(Device.user_id == current_user.user_id).all()
    return [
        DeviceOut(
            device_id=d.device_id,
            device_name=d.device_name,
            os=d.os,
            last_seen=d.last_seen,
            is_online=manager.is_device_online(current_user.user_id, d.device_id)
        )
        for d in devices
    ]


@router.delete("/devices/{device_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
    # Lookup the device owned by this user
    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # 1. Delete the device record
    db.delete(device)

    # 2. Revoke all refresh tokens for this device
    db.query(RefreshToken).filter_by(user_id=user_id, device_id=device_id).delete()
    
    db.commit()

    # 3. Disconnect active WebSocket for this device
    await manager.disconnect_device(user_id, device_id)

    return {"message": f"Device '{device.device_name}' deleted successfully"}


@router.patch("/devices/{device_id}", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def rename_device(
    device_id: str,
    data: DeviceRename,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    name = data.device_name.strip()
    if not (MIN_DEVICE_NAME_LEN <= len(name) <= MAX_DEVICE_NAME_LEN):
        raise HTTPException(status_code=400, detail="device_name length out of bounds")

    _cu: Any = current_user
    user_id: str = _cu.user_id

    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    _dev: Any = device
    _dev.device_name = name
    db.commit()
    db.refresh(device)

    # Broadcast device_updated to other connected devices
    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "device_updated",
            "device": {
                "device_id": _dev.device_id,
                "device_name": _dev.device_name,
                "os": _dev.os
            }
        }
    )

    return DeviceOut(
        device_id=_dev.device_id,
        device_name=_dev.device_name,
        os=_dev.os,
        last_seen=_dev.last_seen,
        is_online=manager.is_device_online(user_id, _dev.device_id)
    )
