import hmac
import hashlib
from app.core.config import Settings

REFRESH_SECRET_KEY = Settings.REFRESH_TOKEN_HASH_KEY

def hash_refresh_token(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise ValueError("Token must be a non-empty string")
    
    return hmac.new(
        REFRESH_SECRET_KEY,
        token.encode(),
        hashlib.sha256
    ).hexdigest()