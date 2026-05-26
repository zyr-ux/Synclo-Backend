import base64
from typing import Any
from app.models.models import User, Clipboard
from app.schemas.schemas import UserWithE2EE, ClipboardOut

def user_to_e2ee_response(user: User) -> UserWithE2EE:
    """
    Extract user E2EE material with proper typing.
    We cast internally to Any to prevent the type checker from 
    complaining about SQLAlchemy Column descriptor types.
    """
    u: Any = user
    return UserWithE2EE(
        email=u.email,
        encrypted_master_key=base64.b64encode(u.encrypted_master_key).decode('utf-8'),
        salt=base64.b64encode(u.salt).decode('utf-8'),
        kdf_version=u.kdf_version
    )

def clipboard_to_response(entry: Clipboard) -> ClipboardOut:
    """
    Extract clipboard with proper typing.
    """
    e: Any = entry
    return ClipboardOut(
        id=e.id,
        ciphertext=base64.b64encode(e.ciphertext).decode('utf-8') if e.ciphertext else None,
        nonce=base64.b64encode(e.nonce).decode('utf-8') if e.nonce else None,
        blob_version=e.blob_version,
        timestamp=e.timestamp,
        updated_at=e.updated_at,
        is_deleted=e.is_deleted,
        deleted_at=e.deleted_at
    )
