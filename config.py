# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Loads from .env file

class Settings:
    # JWT
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32))
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
    REFRESH_TOKEN_HASH_KEY = os.getenv("REFRESH_TOKEN_HASH_KEY", "default-crypt-key").encode('utf-8').ljust(32, b'\0')
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 30))
    # DB
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/clipboard.db")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379") # Default to localhost for dev
    # Features
    ALLOW_AUTO_DEVICE_REGISTRATION = os.getenv("ALLOW_AUTO_DEVICE_REGISTRATION", "true").lower() == "true"

settings = Settings()
