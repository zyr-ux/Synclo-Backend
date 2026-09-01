from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
from app.core.constants import MIN_DEVICE_ID_LEN, MAX_DEVICE_ID_LEN, MIN_DEVICE_NAME_LEN, MAX_DEVICE_NAME_LEN
from app.models.models import Device, User, RefreshToken
from app.schemas.schemas import DeviceRegister, DeviceRename, DeviceOut, PushSubscription
from app.services.auth import get_db, get_current_user
from app.services.serializers import device_to_response
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
    current_user_id: str = current_user.user_id
    existing = db.query(Device).filter(Device.device_id == device.device_id).first()
    if existing:
        if existing.user_id != current_user_id:
            raise HTTPException(status_code=403, detail="Device ID belongs to another user")
        existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        return device_to_response(existing, current_user_id)
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
        return device_to_response(new_device, current_user_id)
    except Exception:
        db.rollback()
        existing = db.query(Device).filter(Device.device_id == device.device_id).first()
        if existing:
            if existing.user_id != current_user_id:
                raise HTTPException(status_code=403, detail="Device ID belongs to another user")
            return device_to_response(existing, current_user_id)
        raise HTTPException(status_code=400, detail="Failed to register device")


@router.get("/devices", response_model=List[DeviceOut], dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).filter(Device.user_id == current_user.user_id).all()
    return [device_to_response(d, current_user.user_id) for d in devices]


@router.delete("/devices/{device_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    db.delete(device)
    db.query(RefreshToken).filter_by(user_id=user_id, device_id=device_id).delete()
    db.commit()

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

    user_id: str = current_user.user_id

    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.device_name = name
    db.commit()
    db.refresh(device)

    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "device_updated",
            "device": {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "os": device.os
            }
        }
    )

    return device_to_response(device, user_id)


@router.put("/devices/{device_id}/push", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def update_device_push(
    device_id: str,
    data: PushSubscription,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.push_subscription = data.push_subscription
    device.push_subscription_updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(device)

    return device_to_response(device, user_id)


@router.delete("/devices/{device_id}/push", response_model=DeviceOut, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def remove_device_push(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    device = db.query(Device).filter_by(device_id=device_id, user_id=user_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.push_subscription = None
    device.push_subscription_updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(device)

    return device_to_response(device, user_id)



