import logging
from logging.handlers import RotatingFileHandler
import os
import re
from typing import Any

os.makedirs("logs", exist_ok=True)


class RedactingFilter(logging.Filter):
    PATTERNS = [
        re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
        re.compile(r"auth_key['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"password['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ]

    @classmethod
    def redact(cls, text: Any) -> Any:
        if not isinstance(text, str):
            return text
        for pattern in cls.PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self.redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
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
