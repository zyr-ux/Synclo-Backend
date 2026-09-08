import asyncio
import sqlite3
import time
from typing import Callable, TypeVar

from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError as SAOperationalError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings

DATABASE_URL = Settings.DATABASE_URL

if DATABASE_URL.startswith("sqlite"):
    db_file_str = DATABASE_URL.replace("sqlite:///", "").split("?")[0]
    if db_file_str and db_file_str != ":memory:":
        from pathlib import Path

        Path(db_file_str).parent.mkdir(parents=True, exist_ok=True)

connect_args = (
    {"check_same_thread": False, "timeout": 30.0} if DATABASE_URL.startswith("sqlite") else {}
)
engine = (
    create_engine(DATABASE_URL, connect_args=connect_args)
    if connect_args
    else create_engine(DATABASE_URL)
)


def configure_sqlite_engine(target_engine) -> None:
    if target_engine.dialect.name != "sqlite":
        return

    @event.listens_for(target_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.close()

    @event.listens_for(target_engine, "begin")
    def begin_sqlite_immediate(connection):
        # Shared connections may already be in an active DBAPI transaction
        if connection.connection.in_transaction:
            return
        connection.exec_driver_sql("BEGIN IMMEDIATE")


if DATABASE_URL.startswith("sqlite"):
    configure_sqlite_engine(engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

T = TypeVar("T")


def is_sqlite_lock_error(exc: BaseException) -> bool:
    if not isinstance(exc, (sqlite3.OperationalError, SAOperationalError)):
        return False
    message = str(exc).lower()
    return "database is locked" in message or "database is busy" in message or "busy" in message


def run_in_write_transaction(
    db: Session,
    fn: Callable[[], T],
    max_retries: int = 5,
    base_delay: float = 0.05,
    max_delay: float = 0.5,
) -> T:
    bind = db.get_bind()
    is_sqlite = bool(bind and bind.dialect.name == "sqlite")
    attempts = max(1, max_retries)

    for attempt in range(attempts):
        try:
            if is_sqlite and db.in_transaction():
                # Authentication and dependencies may have started a read transaction.
                db.rollback()
            result = fn()
            db.commit()
            return result
        except (sqlite3.OperationalError, SAOperationalError) as exc:
            db.rollback()
            if is_sqlite and is_sqlite_lock_error(exc) and attempt + 1 < attempts:
                time.sleep(min(base_delay * (2**attempt), max_delay))
                continue
            raise
        except Exception:
            db.rollback()
            raise

    raise RuntimeError("write transaction exhausted without a result")


async def async_run_in_write_transaction(
    db: Session,
    fn: Callable[[], T],
    max_retries: int = 5,
    base_delay: float = 0.05,
    max_delay: float = 0.5,
) -> T:
    bind = db.get_bind()
    is_sqlite = bool(bind and bind.dialect.name == "sqlite")
    attempts = max(1, max_retries)

    for attempt in range(attempts):
        try:
            if is_sqlite and db.in_transaction():
                # Authentication and dependencies may have started a read transaction.
                db.rollback()
            result = fn()
            db.commit()
            return result
        except (sqlite3.OperationalError, SAOperationalError) as exc:
            db.rollback()
            if is_sqlite and is_sqlite_lock_error(exc) and attempt + 1 < attempts:
                await asyncio.sleep(min(base_delay * (2**attempt), max_delay))
                continue
            raise
        except Exception:
            db.rollback()
            raise

    raise RuntimeError("write transaction exhausted without a result")
