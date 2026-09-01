from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.models import User, BlacklistedToken, Device
from app.core.config import Settings

# SECRET_KEY is guaranteed non-None by Settings (raises RuntimeError at startup if missing)
_raw_secret_key = Settings.SECRET_KEY
assert _raw_secret_key is not None, "SECRET_KEY must be set"
SECRET_KEY: str = _raw_secret_key
ALGORITHM = Settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta if expires_delta else datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        exp: Optional[int] = payload.get("exp")
        device_id: Optional[str] = payload.get("device_id")

        if email is None or exp is None:
            raise credentials_exception

        # Check if token is blacklisted
        if db.query(BlacklistedToken).filter_by(token=token).first():
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        
        # Verify that device is registered for the user
        if not db.query(Device).filter_by(user_id=user.user_id, device_id=device_id).first():
            raise HTTPException(status_code=403, detail="Unauthorized device")
        
        user.current_device_id = device_id
        return user

    except JWTError:
        raise credentials_exception