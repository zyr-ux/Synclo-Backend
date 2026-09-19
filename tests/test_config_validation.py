"""
Test Suite: Configuration & Settings Startup Guards

Scenarios Targeted:
1. Rejection of missing SECRET_KEY at module load time.
2. Rejection of short SECRET_KEY (< 32 characters).
3. Rejection of unsupported JWT signing algorithm.
4. Rejection of missing REFRESH_TOKEN_HASH_KEY.
5. Rejection of short REFRESH_TOKEN_HASH_KEY (< 16 characters).
6. Rejection of missing push providers configuration file.
"""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.core.config import _load_allowed_push_domains


def _run_config_import_subprocess(env_overrides: dict[str, str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", "from app.core.config import Settings"],
        env=env,
        capture_output=True,
        text=True,
    )


def test_settings_rejects_missing_secret_key():
    res = _run_config_import_subprocess({"SECRET_KEY": ""})
    assert res.returncode != 0
    assert "SECRET_KEY environment variable is required for token signing" in res.stderr


def test_settings_rejects_short_secret_key():
    res = _run_config_import_subprocess({"SECRET_KEY": "short_secret"})
    assert res.returncode != 0
    assert "SECRET_KEY must be at least 32 characters long" in res.stderr


def test_settings_rejects_unsupported_algorithm():
    res = _run_config_import_subprocess(
        {"SECRET_KEY": "a" * 32, "ALGORITHM": "RS256"}
    )
    assert res.returncode != 0
    assert "Unsupported JWT signing algorithm: RS256" in res.stderr


def test_settings_rejects_missing_refresh_token_hash_key():
    res = _run_config_import_subprocess(
        {"SECRET_KEY": "a" * 32, "REFRESH_TOKEN_HASH_KEY": ""}
    )
    assert res.returncode != 0
    assert "REFRESH_TOKEN_HASH_KEY environment variable is required" in res.stderr


def test_settings_rejects_short_refresh_token_hash_key():
    res = _run_config_import_subprocess(
        {"SECRET_KEY": "a" * 32, "REFRESH_TOKEN_HASH_KEY": "too_short"}
    )
    assert res.returncode != 0
    assert "REFRESH_TOKEN_HASH_KEY must be at least 16 characters long" in res.stderr


def test_load_allowed_push_domains_missing_file_raises():
    with pytest.raises(RuntimeError, match="Push providers configuration file not found"):
        _load_allowed_push_domains(Path("non_existent_push_providers_path.json"))


def test_settings_rejects_invalid_access_token_expire_minutes():
    valid_keys = {"SECRET_KEY": "a" * 32, "REFRESH_TOKEN_HASH_KEY": "b" * 16}

    # Non-integer
    res = _run_config_import_subprocess({**valid_keys, "ACCESS_TOKEN_EXPIRE_MINUTES": "not_an_int"})
    assert res.returncode != 0
    assert "ACCESS_TOKEN_EXPIRE_MINUTES must be an integer" in res.stderr

    # Lower bound (< 1)
    res = _run_config_import_subprocess({**valid_keys, "ACCESS_TOKEN_EXPIRE_MINUTES": "0"})
    assert res.returncode != 0
    assert "ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 60 minutes" in res.stderr

    # Upper bound (> 60)
    res = _run_config_import_subprocess({**valid_keys, "ACCESS_TOKEN_EXPIRE_MINUTES": "61"})
    assert res.returncode != 0
    assert "ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 60 minutes" in res.stderr


def test_settings_rejects_invalid_refresh_token_expire_days():
    valid_keys = {"SECRET_KEY": "a" * 32, "REFRESH_TOKEN_HASH_KEY": "b" * 16}

    # Non-integer
    res = _run_config_import_subprocess({**valid_keys, "REFRESH_TOKEN_EXPIRE_DAYS": "invalid"})
    assert res.returncode != 0
    assert "REFRESH_TOKEN_EXPIRE_DAYS must be an integer" in res.stderr

    # Lower bound (< 1)
    res = _run_config_import_subprocess({**valid_keys, "REFRESH_TOKEN_EXPIRE_DAYS": "0"})
    assert res.returncode != 0
    assert "REFRESH_TOKEN_EXPIRE_DAYS must be between 1 and 365 days" in res.stderr

    # Upper bound (> 365)
    res = _run_config_import_subprocess({**valid_keys, "REFRESH_TOKEN_EXPIRE_DAYS": "366"})
    assert res.returncode != 0
    assert "REFRESH_TOKEN_EXPIRE_DAYS must be between 1 and 365 days" in res.stderr


def test_settings_accepts_valid_token_expiry_bounds():
    valid_keys = {
        "SECRET_KEY": "a" * 32,
        "REFRESH_TOKEN_HASH_KEY": "b" * 16,
        "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
        "REFRESH_TOKEN_EXPIRE_DAYS": "365",
    }
    res = _run_config_import_subprocess(valid_keys)
    assert res.returncode == 0
