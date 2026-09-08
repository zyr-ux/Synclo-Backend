import asyncio
import sqlite3
import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import (
    async_run_in_write_transaction,
    configure_sqlite_engine,
    run_in_write_transaction,
)


def test_write_transaction_uses_sqlalchemy_immediate_begin_hook():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    with Session(engine) as session:
        session.execute(text("CREATE TABLE values_table (value INTEGER NOT NULL)"))
        session.commit()

        # This read starts SQLAlchemy's implicit transaction before the mutation.
        session.execute(text("SELECT 1")).scalar_one()

        run_in_write_transaction(
            session,
            lambda: session.execute(text("INSERT INTO values_table (value) VALUES (1)")),
        )

        assert session.execute(text("SELECT COUNT(*) FROM values_table")).scalar_one() == 1


def test_write_transaction_handles_shared_connection_across_sessions():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    configure_sqlite_engine(engine)
    with Session(engine) as setup_session:
        setup_session.execute(text("CREATE TABLE values_table (value INTEGER NOT NULL)"))
        setup_session.commit()

    with Session(engine) as first_session:
        first_session.execute(text("SELECT 1")).scalar_one()

    with Session(engine) as second_session:
        run_in_write_transaction(
            second_session,
            lambda: second_session.execute(text("INSERT INTO values_table (value) VALUES (1)")),
        )
        assert second_session.execute(text("SELECT COUNT(*) FROM values_table")).scalar_one() == 1


def test_busy_retry_rolls_back_failed_mutation_before_retry(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with Session(engine) as session:
        session.execute(text("CREATE TABLE values_table (value INTEGER PRIMARY KEY)"))
        session.commit()
        attempts = 0

        def mutate():
            nonlocal attempts
            attempts += 1
            session.execute(text("INSERT INTO values_table (value) VALUES (1)"))
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr("app.core.database.time.sleep", lambda _: None)
        run_in_write_transaction(session, mutate, max_retries=2)

        assert attempts == 2
        assert session.execute(text("SELECT COUNT(*) FROM values_table")).scalar_one() == 1


def test_auth_write_transaction_retries_on_contention(monkeypatch):
    from uuid import uuid4
    from app.core.database import Base
    from app.models.models import User

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)

    attempts = 0
    with Session(engine) as session:

        def mutate():
            nonlocal attempts
            attempts += 1
            user = User(
                user_id=str(uuid4()),
                email="retry_test@synclo.app",
                auth_key_hash="hash",
                encrypted_master_key=b"emk",
                salt=b"salt",
                kdf_version=1,
                recovery_wrapped_master_key=b"rwmk",
                recovery_key_verifier="rkv",
            )
            session.add(user)
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")
            return user

        monkeypatch.setattr("app.core.database.time.sleep", lambda _: None)
        user = run_in_write_transaction(session, mutate, max_retries=3)
        assert attempts == 2
        assert session.query(User).filter_by(email="retry_test@synclo.app").count() == 1
        assert user.email == "retry_test@synclo.app"


@pytest.mark.asyncio
async def test_async_write_transaction_retries_on_contention():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with Session(engine) as session:
        session.execute(text("CREATE TABLE async_values (value INTEGER PRIMARY KEY)"))
        session.commit()
        attempts = 0

        def mutate():
            nonlocal attempts
            attempts += 1
            session.execute(text("INSERT INTO async_values (value) VALUES (42)"))
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")

        await async_run_in_write_transaction(session, mutate, max_retries=3, base_delay=0.01)
        assert attempts == 2
        assert session.execute(text("SELECT COUNT(*) FROM async_values")).scalar_one() == 1


@pytest.mark.asyncio
async def test_async_write_transaction_sleep_yields_loop():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with Session(engine) as session:
        session.execute(text("CREATE TABLE async_yield (value INTEGER PRIMARY KEY)"))
        session.commit()
        attempts = 0
        concurrent_task_ran = False

        def mutate():
            nonlocal attempts
            attempts += 1
            session.execute(text("INSERT INTO async_yield (value) VALUES (99)"))
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")

        async def concurrent_worker():
            nonlocal concurrent_task_ran
            await asyncio.sleep(0.01)
            concurrent_task_ran = True

        task = asyncio.create_task(concurrent_worker())
        await async_run_in_write_transaction(session, mutate, max_retries=3, base_delay=0.05)
        await task

        assert attempts == 2
        assert concurrent_task_ran is True
        assert session.execute(text("SELECT COUNT(*) FROM async_yield")).scalar_one() == 1


def test_file_backed_sqlite_concurrent_write_transactions(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    db_path = tmp_path / "concurrent_wal.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)

    with Session(engine) as session:
        session.execute(
            text(
                "CREATE TABLE concurrent_test (id INTEGER PRIMARY KEY AUTOINCREMENT, worker_id INT)"
            )
        )
        session.commit()

    num_workers = 10

    def worker(worker_id: int):
        with Session(engine) as worker_session:

            def mutate():
                worker_session.execute(
                    text("INSERT INTO concurrent_test (worker_id) VALUES (:wid)"),
                    {"wid": worker_id},
                )

            run_in_write_transaction(worker_session, mutate, max_retries=10, base_delay=0.01)

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_workers)]
        for f in futures:
            f.result()

    with Session(engine) as verify_session:
        count = verify_session.execute(text("SELECT COUNT(*) FROM concurrent_test")).scalar_one()
        assert count == num_workers
    engine.dispose()
