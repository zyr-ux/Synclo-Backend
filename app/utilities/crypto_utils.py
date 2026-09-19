import base64
import hashlib
import hmac

from app.core.config import Settings

REFRESH_SECRET_KEY = Settings.REFRESH_TOKEN_HASH_KEY


def hash_refresh_token(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise ValueError("Token must be a non-empty string")

    return hmac.new(REFRESH_SECRET_KEY, token.encode(), hashlib.sha256).hexdigest()


def strict_b64decode(value: str, field_name: str = "field") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 encoding for {field_name}: {exc}") from exc
