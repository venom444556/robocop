"""Shared test fixtures for the malware analysis platform test suite."""

import sys
import os
import asyncio
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Ensure the backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database import Base, get_db
from main import app


# ---------------------------------------------------------------------------
# Event-loop fixture (session-scoped so all async tests share one loop)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create an in-memory SQLite async engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(test_engine):
    """Create an async database session bound to the test engine."""
    async_session_factory = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session_factory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# FastAPI test-client fixture
# ---------------------------------------------------------------------------

def _clear_rate_limiter_buckets():
    """Clear all token buckets in every RateLimitMiddleware on the app.

    This prevents rate-limiting from leaking between test functions.
    """
    for middleware in app.user_middleware:
        # middleware is a Middleware dataclass with .cls and .kwargs
        pass
    # Walk the middleware stack to find the RateLimitMiddleware instance
    mw = app.middleware_stack
    while mw is not None:
        if hasattr(mw, "buckets"):
            mw.buckets.clear()
        # Starlette wraps middlewares in layers; try common attribute names
        mw = getattr(mw, "app", None)


@pytest_asyncio.fixture(scope="function")
async def client(test_engine):
    """Provide an httpx.AsyncClient wired to the FastAPI app with a test DB."""
    import httpx

    # Build a session factory that uses our in-memory test engine
    async_session_factory = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _override_get_db():
        async with async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db

    # Reset rate limiter state so tests don't interfere with each other
    _clear_rate_limiter_buckets()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()
