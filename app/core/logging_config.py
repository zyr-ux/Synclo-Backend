import logging
from logging.handlers import RotatingFileHandler
import os

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

logger = logging.getLogger("clipboard_sync")
logger.setLevel(logging.DEBUG)

# File handler with rotation
file_handler = RotatingFileHandler("logs/server.log", maxBytes=1_000_000, backupCount=3)
file_handler.setLevel(logging.DEBUG)

# Console handler (optional)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Attach handlers
logger.addHandler(file_handler)
logger.addHandler(console_handler)