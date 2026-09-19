from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi_limiter.depends import RateLimiter
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from app.core.constants import (
    MIN_DEVICE_ID_LEN,
    MAX_DEVICE_ID_LEN,
    MIN_DEVICE_NAME_LEN,
    MAX_DEVICE_NAME_LEN,
)
from app.database.engine import get_db, run_in_write_transaction
from app.database.models import Device, RefreshToken
from app.database.schemas import (
    DeviceRegister,
    DeviceRename,
    DeviceOut,
    PushSubscription,
    AuthContext,
)
from app.services.auth import get_auth_context
from app.services.serializers import device_to_response
from app.services.push_service import encrypt_push_subscription
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post(
    "/devices/register",
    response_model=DeviceOut,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
)
async def register_device(
    device: DeviceRegister,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    if not (MIN_DEVICE_ID_LEN <= len(device.device_id) <= MAX_DEVICE_ID_LEN):
        raise HTTPException(status_code=400, detail="device_id length out of bounds")
    current_user_id: str = auth.user.user_id

    def mutate() -> tuple[Device, bool]:
        existing = db.scalars(
            select(Device).where(
                Device.device_id == device.device_id, Device.user_id == current_user_id
            )
        ).first()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            return existing, False

        new_device = Device(
            device_id=device.device_id,
            device_name=device.device_name,
            os=device.os,
            user_id=current_user_id,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(new_device)
        return new_device, True

    registered_device, created = run_in_write_transaction(db, mutate)
    db.refresh(registered_device)
    if created:
        await manager.broadcast_to_user(
            user_id=current_user_id,
            message={
                "type": "device_added",
                "device": {
                    "device_id": registered_device.device_id,
                    "device_name": registered_device.device_name,
                    "os": registered_device.os,
                },
            },
        )
    return device_to_response(registered_device, current_user_id)


@router.get(
    "/devices",
    response_model=List[DeviceOut],
    dependencies=[Depends(RateLimiter(times=20, seconds=60))],
)
def get_devices(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id = auth.user.user_id
    devices = list(db.scalars(select(Device).where(Device.user_id == user_id)).all())
    return [device_to_response(d, user_id) for d in devices]


@router.delete("/devices/{device_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    device = db.scalars(
        select(Device).where(Device.device_id == device_id, Device.user_id == user_id)
    ).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    def mutate() -> None:
        db.delete(device)
        db.execute(
            delete(RefreshToken).where(
                RefreshToken.user_id == user_id, RefreshToken.device_id == device_id
            )
        )

    run_in_write_transaction(db, mutate)

    await manager.disconnect_device(user_id, device_id)

    return {"message": f"Device '{device.device_name}' deleted successfully"}


@router.patch(
    "/devices/{device_id}",
    response_model=DeviceOut,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
)
async def rename_device(
    device_id: str,
    data: DeviceRename,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    name = data.device_name.strip()
    if not (MIN_DEVICE_NAME_LEN <= len(name) <= MAX_DEVICE_NAME_LEN):
        raise HTTPException(status_code=400, detail="device_name length out of bounds")

    user_id: str = auth.user.user_id

    device = db.scalars(
        select(Device).where(Device.device_id == device_id, Device.user_id == user_id)
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    def mutate() -> None:
        device.device_name = name

    run_in_write_transaction(db, mutate)
    db.refresh(device)

    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "device_updated",
            "device": {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "os": device.os,
            },
        },
    )

    return device_to_response(device, user_id)


@router.put(
    "/devices/{device_id}/push",
    response_model=DeviceOut,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
)
async def update_device_push(
    device_id: str,
    data: PushSubscription,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    device = db.scalars(
        select(Device).where(Device.device_id == device_id, Device.user_id == user_id)
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    encrypted_subscription = encrypt_push_subscription(data.push_subscription)

    def mutate() -> None:
        device.push_subscription = encrypted_subscription
        device.push_subscription_updated_at = datetime.now(timezone.utc)

    run_in_write_transaction(db, mutate)
    db.refresh(device)

    return device_to_response(device, user_id)


@router.delete(
    "/devices/{device_id}/push",
    response_model=DeviceOut,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
)
async def remove_device_push(
    device_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    device = db.scalars(
        select(Device).where(Device.device_id == device_id, Device.user_id == user_id)
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    def mutate() -> None:
        device.push_subscription = None
        device.push_subscription_updated_at = datetime.now(timezone.utc)

    run_in_write_transaction(db, mutate)
    db.refresh(device)

    return device_to_response(device, user_id)
