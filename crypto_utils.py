import hmac
import hashlib
from Crypto.Cipher import AES
import base64
from config import Settings

# Server-side secret key (store this securely in prod)
REFRESH_SECRET_KEY = Settings.REFRESH_TOKEN_HASH_KEY

def encrypt_clipboard(plaintext: str, key: bytes) -> (bytes, bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce + tag + ciphertext, cipher.nonce  # Return full blob and nonce

def decrypt_clipboard(encrypted_blob: bytes, key: bytes) -> str:
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    ciphertext = encrypted_blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

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