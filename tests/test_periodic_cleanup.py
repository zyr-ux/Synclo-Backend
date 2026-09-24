# Test Suite: Periodic Background Cleanup & Maintenance Tasks

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.database.engine import run_in_write_transaction
from app.database.models import BlacklistedToken, Clipboard, RefreshToken, User
from app.main import app, periodic_cleanup
from app.services.cleanup_service import CleanupResult, run_all_cleanup


# 1. End-to-end execution of all cleanup routines purging expired tokens and tombstones.
def test_run_all_cleanup_end_to_end(db_session):
    now = datetime.now(timezone.utc)
    past = now - timedelta(days= Settings.TOMBSTONE_RETENTION_DAYS + 5)
    future = now + timedelta(days=1)

    user = User(
        user_id="user-cleanup-all",
        email="cleanup_all@synclo.app",
        auth_key_hash="hash",
        salt=b"salt",
        encrypted_master_key=b"emk",
        kdf_version=1,
        recovery_wrapped_master_key=b"rec",
        recovery_key_verifier="ver",
        sync_sequence=0,
    )

    bt_expired = BlacklistedToken(token="bt_expired", expiry=past)
    bt_active = BlacklistedToken(token="bt_active", expiry=future)

    rt_expired = RefreshToken(
        user_id="user-cleanup-all",
        token="rt_expired_hash",
        expiry=past,
        device_id="dev-1",
        token_id="tok-1",
    )
    rt_active = RefreshToken(
        user_id="user-cleanup-all",
        token="rt_active_hash",
        expiry=future,
        device_id="dev-1",
        token_id="tok-2",
    )

    clip_old_tombstone = Clipboard(
        clipboard_id="clip-tombstone-expired",
        user_id="user-cleanup-all",
        ciphertext=None,
        nonce=None,
        timestamp=past,
        updated_at=past,
        is_deleted=True,
        deleted_at=past,
        change_number=1,
    )

    clip_stale_active = Clipboard(
        clipboard_id="clip-stale-active",
        user_id="user-cleanup-all",
        ciphertext=b"old_cipher",
        nonce=b"old_nonce",
        timestamp=past,
        updated_at=past,
        is_deleted=False,
        is_pinned=False,
        change_number=2,
    )

    def mutate():
        db_session.add_all([
            user,
            bt_expired,
            bt_active,
            rt_expired,
            rt_active,
            clip_old_tombstone,
            clip_stale_active,
        ])

    run_in_write_transaction(db_session, mutate)

    result = run_all_cleanup(db_session)

    assert isinstance(result, CleanupResult)
    assert result.failures == 0
    assert len(result.tombstones) == 1
    user_id, tombstone = result.tombstones[0]
    assert user_id == "user-cleanup-all"
    assert tombstone["id"] == "clip-stale-active"
    assert tombstone["is_deleted"] is True

    remaining_bt = list(db_session.scalars(select(BlacklistedToken.token)).all())
    assert "bt_active" in remaining_bt
    assert "bt_expired" not in remaining_bt

    remaining_rt = list(db_session.scalars(select(RefreshToken.token)).all())
    assert "rt_active_hash" in remaining_rt
    assert "rt_expired_hash" not in remaining_rt

    remaining_clips = {
        c.clipboard_id: c for c in db_session.scalars(select(Clipboard)).all()
    }
    assert "clip-tombstone-expired" not in remaining_clips
    assert "clip-stale-active" in remaining_clips
    assert remaining_clips["clip-stale-active"].is_deleted is True
    assert remaining_clips["clip-stale-active"].ciphertext is None


# 2. Failure isolation tracking partial failures when a cleanup subroutine returns False.
def test_run_all_cleanup_handles_subtask_failure(db_session, monkeypatch):
    def mock_broken_tokens(db):
        return False

    monkeypatch.setattr(
        "app.services.cleanup_service.cleanup_expired_blacklisted_tokens",
        mock_broken_tokens,
    )

    result = run_all_cleanup(db_session)
    assert result.failures >= 1


# 3. Periodic cleanup loop skips execution cycle when Redis distributed lock is held.
@pytest.mark.asyncio
async def test_periodic_cleanup_skips_when_lock_not_acquired():
    mock_redis = AsyncMock()
    mock_lock = AsyncMock()
    mock_lock.acquire = AsyncMock(return_value=False)
    mock_redis.lock = MagicMock(return_value=mock_lock)

    with patch.object(app.state, "redis", mock_redis, create=True):
        with patch("app.main._execute_cleanup") as mock_exec:
            task = asyncio.create_task(periodic_cleanup())
            await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            mock_lock.acquire.assert_called()
            mock_exec.assert_not_called()
            mock_lock.release.assert_not_called()


# 4. Periodic cleanup broadcasts tombstones and dispatches push notifications to affected users.
@pytest.mark.asyncio
async def test_periodic_cleanup_broadcasts_and_pushes_when_tombstones_found():
    mock_redis = AsyncMock()
    mock_lock = AsyncMock()
    mock_lock.acquire = AsyncMock(return_value=True)
    mock_lock.release = AsyncMock()
    mock_redis.lock = MagicMock(return_value=mock_lock)

    sample_tombstones = [
        ("user-target-1", {"type": "clipboard_sync", "id": "clip-del-1"}),
        ("user-target-1", {"type": "clipboard_sync", "id": "clip-del-2"}),
    ]
    mock_result = CleanupResult(tombstones=sample_tombstones, failures=0)

    with patch.object(app.state, "redis", mock_redis, create=True):
        with patch("app.main._execute_cleanup", return_value=mock_result):
            with patch("app.main.manager.broadcast_to_user", new_callable=AsyncMock) as mock_bcast:
                with patch("app.main.launch_background_push") as mock_push:
                    task = asyncio.create_task(periodic_cleanup())
                    await asyncio.sleep(0.02)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                    assert mock_bcast.call_count == 2
                    mock_push.assert_called_once_with(user_id="user-target-1")
                    mock_lock.release.assert_called_once()
