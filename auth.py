from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, BlacklistedToken, Device
from utils import cleanup_expired_blacklisted_tokens
from config import Settings

# Secret key (change this in production!)
SECRET_KEY = Settings.SECRET_KEY
ALGORITHM = Settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = Settings.ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        exp: int = payload.get("exp")
        device_id: str = payload.get("device_id")

        if email is None or exp is None:
            raise credentials_exception

        # Cleanup expired blacklisted tokens
        cleanup_expired_blacklisted_tokens(db)

        # Check if token is blacklisted
        if db.query(BlacklistedToken).filter_by(token=token).first():
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        
        # Verify that device is registered for the user
        if not db.query(Device).filter_by(user_id=user.id, device_id=device_id).first():
            raise HTTPException(status_code=403, detail="Unauthorized device")
        
        return user

    except JWTError:
        raise credentials_exception

def get_user_from_token_ws(token: str):
    db = SessionLocal()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        device_id: str = payload.get("device_id")

        if email is None or device_id is None:
            return None

        # Check if token is blacklisted
        if db.query(BlacklistedToken).filter_by(token=token).first():
            return None

        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None

        # Check if device belongs to this user
        device = db.query(Device).filter_by(user_id=user.id, device_id=device_id).first()
        
        if device is None:
            return None

        return user

    except JWTError:
        return None
    finally:
        db.close()