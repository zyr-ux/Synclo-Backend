import logging
import os
import tomllib
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

_logger = logging.getLogger(__name__)

_pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
if not _pyproject_path.exists():
    raise RuntimeError(f"pyproject.toml not found at {_pyproject_path}")

try:
    with open(_pyproject_path, "rb") as _f:
        _pyproject_data = tomllib.load(_f).get("project", {})
except Exception as _e:
    raise RuntimeError(f"Failed to parse pyproject.toml: {_e}") from _e


def _load_allowed_push_domains(file_path: str | None = None) -> set[str]:
    default_domains = {"ntfy.sh", "push.nextcloud.com", "up.kde.org", "unifiedpush.org"}
    path = (
        Path(file_path)
        if file_path
        else (Path(__file__).resolve().parents[1] / "utilities" / "push_providers.json")
    )
    if not path.exists():
        return default_domains
    try:
        import json

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            domains = set(data.get("allowed_domains", []))
            for p in data.get("providers", []):
                if "domain" in p:
                    domains.add(p["domain"])
            return domains or default_domains
    except Exception as exc:
        _logger.warning("Failed to load push providers from %s: %s. Using defaults.", path, exc)
        return default_domains


class Settings:
    PROJECT_NAME: str = _pyproject_data["name"]
    VERSION: str = _pyproject_data["version"]
    DESCRIPTION: str = _pyproject_data["description"]

    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY environment variable is required for token signing")
    if len(SECRET_KEY) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters long")

    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    if ALGORITHM not in {"HS256", "HS384", "HS512"}:
        raise RuntimeError(f"Unsupported JWT signing algorithm: {ALGORITHM}")

    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

    REFRESH_TOKEN_HASH_KEY = os.getenv("REFRESH_TOKEN_HASH_KEY")
    if not REFRESH_TOKEN_HASH_KEY:
        raise RuntimeError(
            "REFRESH_TOKEN_HASH_KEY environment variable is required for refresh token HMAC"
        )
    if len(REFRESH_TOKEN_HASH_KEY) < 16:
        raise RuntimeError("REFRESH_TOKEN_HASH_KEY must be at least 16 characters long")
    REFRESH_TOKEN_HASH_KEY = REFRESH_TOKEN_HASH_KEY.encode("utf-8")

    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 30))
    TOMBSTONE_RETENTION_DAYS = int(os.getenv("TOMBSTONE_RETENTION_DAYS", "30"))

    CLIPBOARD_RETENTION_DAYS = int(os.getenv("CLIPBOARD_RETENTION_DAYS", "30"))

    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/synclo.db")
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

    HTTPS_ONLY = os.getenv("HTTPS_ONLY", "false").lower() in ("true", "1", "yes")

    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
    ALLOW_ARBITRARY_PUSH_ENDPOINTS = os.getenv(
        "ALLOW_ARBITRARY_PUSH_ENDPOINTS", "false"
    ).lower() in ("true", "1", "yes")
    ALLOW_LOCAL_PUSH_ENDPOINTS = os.getenv("ALLOW_LOCAL_PUSH_ENDPOINTS", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    PUSH_PROVIDERS_FILE = os.getenv(
        "PUSH_PROVIDERS_FILE",
        str(Path(__file__).resolve().parents[1] / "utilities" / "push_providers.json"),
    )
    ALLOWED_PUSH_DOMAINS = _load_allowed_push_domains(PUSH_PROVIDERS_FILE)

    TRUSTED_PROXIES = [
        p.strip() for p in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip()
    ]

    BACKUP_ENCRYPTION_KEY = os.getenv("BACKUP_ENCRYPTION_KEY", None)
    BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "30"))
    BACKUP_DIR = os.getenv("BACKUP_DIR", "data/backups")

    if ENVIRONMENT == "production":
        if ALLOW_ARBITRARY_PUSH_ENDPOINTS:
            raise RuntimeError("ALLOW_ARBITRARY_PUSH_ENDPOINTS cannot be enabled in production")
        if ALLOW_LOCAL_PUSH_ENDPOINTS:
            raise RuntimeError("ALLOW_LOCAL_PUSH_ENDPOINTS cannot be enabled in production")
