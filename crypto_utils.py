import hmac
import hashlib
from config import Settings

# Server-side secret key (store this securely in prod)
REFRESH_SECRET_KEY = Settings.REFRESH_TOKEN_HASH_KEY

def hash_refresh_token(token: str) -> str:
    """Hash a refresh token using HMAC-SHA256.
    
    Args:
        token: The refresh token string to hash
        
    Returns:
        Hexadecimal digest of the HMAC
        
    Raises:
        ValueError: If token is empty or not a string
    """
    if not isinstance(token, str) or not token:
        raise ValueError("Token must be a non-empty string")
    
    return hmac.new(
        REFRESH_SECRET_KEY,
        token.encode(),
        hashlib.sha256
    ).hexdigest()