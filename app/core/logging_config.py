import logging
from logging.handlers import RotatingFileHandler
import os
import re

os.makedirs("logs", exist_ok=True)

class RedactingFilter(logging.Filter):
    PATTERNS = [
        re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
        re.compile(r"auth_key['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"password['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.PATTERNS:
                msg = pattern.sub("[REDACTED]", msg)
            record.msg = msg
        return True

logger = logging.getLogger("clipboard_sync")
logger.setLevel(logging.DEBUG)
logger.addFilter(RedactingFilter())

file_handler = RotatingFileHandler("logs/server.log", maxBytes=1_000_000, backupCount=3)
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)