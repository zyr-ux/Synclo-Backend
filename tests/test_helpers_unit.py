"""
Unit tests for app/utilities/datetime_utils.py, app/utilities/crypto_utils.py, and RedactingFilter.

Covers pure helper functions and RedactingFilter to ensure strict zero-knowledge
and data integrity guarantees without test bias:
- hash_refresh_token: type safety, rejection of empty/invalid inputs, determinism, HMAC integrity
- strict_b64decode: rejection of non-string inputs, invalid base64, corrupt padding, boundary inputs
- ensure_utc / to_iso_utc / parse_iso_utc: None-safety, naive vs aware handling, ISO 8601 'Z' conformity, round-tripping
- RedactingFilter: log sanitization for bearer tokens, credentials, and emails without crashing on non-strings or bad records
"""

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, cast
from unittest.mock import MagicMock
import pytest

from app.core.logging_config import RedactingFilter
from app.utilities.crypto_utils import hash_refresh_token, strict_b64decode
from app.utilities.datetime_utils import ensure_utc, parse_iso_utc, to_iso_utc


# =====================================================================
# hash_refresh_token
# =====================================================================


def test_hash_refresh_token_valid_output():
    token = "synclo_test_refresh_token_xyz_12345"
    h1 = hash_refresh_token(token)
    h2 = hash_refresh_token(token)

    assert isinstance(h1, str)
    assert len(h1) == 64  # SHA-256 hex digest length
    assert h1 == h2  # Deterministic given the same secret and token


def test_hash_refresh_token_sensitivity():
    token_a = "token_variant_a"
    token_b = "token_variant_b"
    assert hash_refresh_token(token_a) != hash_refresh_token(token_b)


@pytest.mark.parametrize("invalid_token", ["", None, 12345, b"bytes_token", [], {}])
def test_hash_refresh_token_rejects_empty_or_non_string(invalid_token):
    with pytest.raises(ValueError, match="Token must be a non-empty string"):
        hash_refresh_token(invalid_token)


# =====================================================================
# strict_b64decode
# =====================================================================


def test_strict_b64decode_valid_payload():
    original_data = b"synclo-zero-knowledge-secret-payload\x00\xff\xfe"
    encoded = base64.b64encode(original_data).decode("utf-8")

    decoded = strict_b64decode(encoded, "test_field")
    assert decoded == original_data


def test_strict_b64decode_empty_string():
    assert strict_b64decode("", "empty_field") == b""


@pytest.mark.parametrize("non_string_val", [None, 1234, b"raw_bytes", ["list"], {"k": "v"}])
def test_strict_b64decode_rejects_non_strings(non_string_val):
    with pytest.raises(ValueError, match="test_payload must be a string"):
        strict_b64decode(non_string_val, "test_payload")


@pytest.mark.parametrize(
    "corrupt_base64",
    [
        "not_base64!@#$%",
        "abcde",  # Invalid length / missing padding
        "====",   # Only padding
        "abc===", # Excess padding
        "ab",     # Invalid base64 chunk length without padding
    ],
)
def test_strict_b64decode_rejects_malformed_base64(corrupt_base64):
    with pytest.raises(ValueError, match="Invalid base64 encoding for custom_field"):
        strict_b64decode(corrupt_base64, "custom_field")


# =====================================================================
# ensure_utc
# =====================================================================


def test_ensure_utc_none_returns_none():
    assert ensure_utc(None) is None


def test_ensure_utc_naive_datetime():
    naive = datetime(2025, 1, 15, 12, 30, 45)
    utc = ensure_utc(naive)

    assert utc.tzinfo is timezone.utc
    assert utc.year == 2025
    assert utc.month == 1
    assert utc.day == 15
    assert utc.hour == 12
    assert utc.minute == 30
    assert utc.second == 45


def test_ensure_utc_aware_conversion():
    # Offset +05:30 (e.g. IST)
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    ist_dt = datetime(2025, 1, 15, 17, 30, 0, tzinfo=ist_tz)

    utc = ensure_utc(ist_dt)
    assert utc.tzinfo is timezone.utc
    # 17:30 - 05:30 = 12:00 UTC
    assert utc.hour == 12
    assert utc.minute == 0
    assert utc.timestamp() == ist_dt.timestamp()


def test_ensure_utc_already_utc():
    utc_dt = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    res = ensure_utc(utc_dt)
    assert res == utc_dt
    assert res.tzinfo is timezone.utc


# =====================================================================
# to_iso_utc
# =====================================================================


def test_to_iso_utc_none_returns_none():
    assert to_iso_utc(None) is None


def test_to_iso_utc_formatting_contains_z_suffix():
    dt = datetime(2025, 6, 1, 14, 15, 30, 123456, tzinfo=timezone.utc)
    res = to_iso_utc(dt)
    assert res == "2025-06-01T14:15:30.123456Z"
    assert not res.endswith("+00:00")


def test_to_iso_utc_naive_converted_to_z():
    naive = datetime(2025, 6, 1, 14, 15, 30)
    res = to_iso_utc(naive)
    assert res == "2025-06-01T14:15:30Z"


def test_to_iso_utc_duck_typed_isoformat():
    class CustomDateLike:
        def isoformat(self):
            return "2025-12-31T23:59:59+00:00"

    obj = CustomDateLike()
    res = to_iso_utc(cast(Any, obj))
    assert res == "2025-12-31T23:59:59Z"


def test_to_iso_utc_fallback_str():
    assert to_iso_utc(cast(Any, "already_a_string")) == "already_a_string"
    assert to_iso_utc(cast(Any, 123456)) == "123456"


# =====================================================================
# parse_iso_utc
# =====================================================================


def test_parse_iso_utc_with_z():
    s = "2025-04-10T08:30:00Z"
    dt = parse_iso_utc(s)
    assert dt.tzinfo is timezone.utc
    assert dt.year == 2025
    assert dt.month == 4
    assert dt.day == 10
    assert dt.hour == 8
    assert dt.minute == 30


def test_parse_iso_utc_with_offset():
    # 14:00+05:30 is 08:30 UTC
    s = "2025-04-10T14:00:00+05:30"
    dt = parse_iso_utc(s)
    assert dt.tzinfo is timezone.utc
    assert dt.hour == 8
    assert dt.minute == 30


def test_parse_iso_utc_roundtrip():
    original = datetime(2025, 8, 20, 19, 45, 12, 654321, tzinfo=timezone.utc)
    iso_str = to_iso_utc(original)
    assert iso_str is not None
    parsed = parse_iso_utc(iso_str)
    assert parsed == original
    assert parsed.tzinfo is timezone.utc


def test_parse_iso_utc_invalid_string():
    with pytest.raises(ValueError):
        parse_iso_utc("not-a-timestamp")


# =====================================================================
# RedactingFilter
# =====================================================================


def test_redacting_filter_redact_non_string():
    assert RedactingFilter.redact(None) is None
    assert RedactingFilter.redact(12345) == 12345
    assert RedactingFilter.redact(["a", "b"]) == ["a", "b"]


def test_redacting_filter_redacts_bearer_tokens():
    raw = "Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz_123-abc"
    redacted = RedactingFilter.redact(raw)
    assert "[REDACTED]" in redacted
    assert "eyJhbGci" not in redacted


def test_redacting_filter_redacts_auth_key_and_password():
    raw1 = 'Payload received with auth_key: "super_secret_auth_key_abc"'
    raw2 = "Setting auth_key='secret_key_123' in session"
    raw3 = 'User tried password: "MyClearPassword123!"'
    raw4 = "Database error at password='PlainTextPassword'"

    for raw in [raw1, raw2, raw3, raw4]:
        redacted = RedactingFilter.redact(raw)
        assert "[REDACTED]" in redacted
        assert "super_secret" not in redacted
        assert "PlainTextPassword" not in redacted
        assert "MyClearPassword123!" not in redacted


def test_redacting_filter_redacts_emails():
    raw = "Notification dispatched to user.name+tag@sub.domain.org and backup@synclo.app"
    redacted = RedactingFilter.redact(raw)
    assert "[REDACTED]" in redacted
    assert "user.name" not in redacted
    assert "backup@synclo.app" not in redacted


def test_redacting_filter_multi_pattern_mixed_string():
    raw = (
        "User alice@example.com logged in via Bearer token_secret_123 "
        "with auth_key=\"key_xyz\" and password='pwd'"
    )
    redacted = RedactingFilter.redact(raw)
    assert "alice@example.com" not in redacted
    assert "token_secret_123" not in redacted
    assert "key_xyz" not in redacted
    assert "pwd" not in redacted
    assert redacted.count("[REDACTED]") == 4


def test_redacting_filter_clean_message_untouched():
    raw = "Database connection pool initialized with 10 connections."
    assert RedactingFilter.redact(raw) == raw


def test_redacting_filter_log_record_integration():
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=100,
        msg="Login failed for user %s with auth_key: '%s'",
        args=("bob@synclo.app", "secret_auth_val"),
        exc_info=None,
    )

    filt = RedactingFilter()
    result = filt.filter(record)

    assert result is True
    assert record.args == ()
    assert "bob@synclo.app" not in record.msg
    assert "secret_auth_val" not in record.msg
    assert "[REDACTED]" in record.msg


def test_redacting_filter_handles_malformed_record_gracefully():
    broken_record = MagicMock()
    broken_record.getMessage.side_effect = RuntimeError("Broken record message formatting")

    filt = RedactingFilter()
    # Must not raise an unhandled exception, must return True
    assert filt.filter(broken_record) is True
