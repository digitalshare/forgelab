"""Test harness for database-backed identity tests.

Integration tests run against a real PostgreSQL database created from the
Alembic migrations — not `Base.metadata.create_all`. The migrations are the
artifact that ships, so they are what gets exercised; creating tables from
metadata would hide a broken or missing migration entirely.

If Postgres is unreachable the database tests skip rather than fail, so the
suite still runs on a machine without Docker. A skip is visible in the summary;
treat it as "unverified", not "passed".
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path

import pytest
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from alembic import command
from forgelab_api.db.session import get_session
from forgelab_api.main import create_app

TEST_DATABASE_URL = os.getenv(
    "FORGELAB_TEST_DATABASE_URL",
    "postgresql+asyncpg://forgelab:forgelab@localhost:5432/forgelab_test",
)

_API_ROOT = Path(__file__).resolve().parent.parent


def _asyncpg_dsn(url: str, *, database: str | None = None) -> str:
    """Convert a SQLAlchemy URL to a bare asyncpg DSN, optionally repointing it."""
    dsn = url.replace("postgresql+asyncpg://", "postgresql://")
    if database is not None:
        dsn = dsn.rsplit("/", 1)[0] + f"/{database}"
    return dsn


async def _ensure_database() -> None:
    """Create the test database if it does not already exist."""
    import asyncpg

    name = TEST_DATABASE_URL.rsplit("/", 1)[-1]
    conn = await asyncpg.connect(_asyncpg_dsn(TEST_DATABASE_URL, database="postgres"))
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", name)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


async def _server_reachable() -> bool:
    import asyncpg

    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(_asyncpg_dsn(TEST_DATABASE_URL, database="postgres")), timeout=5
        )
    except Exception:
        return False
    await conn.close()
    return True


@pytest.fixture(scope="session")
def migrated_database() -> str:
    """A test database with every migration applied. Skips if Postgres is down."""
    if not asyncio.run(_server_reachable()):
        pytest.skip(
            "PostgreSQL is not reachable — start it with `docker compose up -d` "
            "or set FORGELAB_TEST_DATABASE_URL to run database tests."
        )

    asyncio.run(_ensure_database())

    config = Config(str(_API_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_API_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.upgrade(config, "head")

    return TEST_DATABASE_URL


@pytest.fixture(scope="session")
def engine(migrated_database: str) -> Iterator[AsyncEngine]:
    created = create_async_engine(migrated_database, poolclass=NullPool)
    yield created
    asyncio.run(created.dispose())


@pytest.fixture
async def db_session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """A session wrapped in a transaction that is always rolled back.

    Tests share one migrated database, so each must leave no trace. Helpers under
    test call `flush()` rather than `commit()`, so rows are visible within the
    test and vanish afterwards.
    """
    async with engine.connect() as connection:
        transaction = await connection.begin()
        session = AsyncSession(
            bind=connection,
            expire_on_commit=False,
            # Route handlers call commit(). Without this the commit would end
            # the outer transaction and the test's changes would persist;
            # create_savepoint makes each commit release a SAVEPOINT instead,
            # so the outer rollback still undoes everything.
            join_transaction_mode="create_savepoint",
        )
        try:
            yield session
        finally:
            await session.close()
            # A test that provokes an IntegrityError leaves the transaction
            # already deassociated; rolling it back again warns noisily.
            if transaction.is_active:
                await transaction.rollback()


@pytest.fixture
async def api_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """An HTTP client for the app, sharing the test's database session.

    httpx over ASGI rather than starlette's TestClient: TestClient drives the
    app from a separate thread and event loop, and an AsyncSession cannot be
    shared across loops. This keeps request handling in the same loop as the
    fixture that owns the session.
    """
    app = create_app()

    async def _session_override() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_session] = _session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()
