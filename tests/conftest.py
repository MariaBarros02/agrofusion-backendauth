# conftest.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from app.main import app
from app.core.database import get_db
from app.models.users import Users
from app.core.config import settings


# ======================================================
# Constantes
# ======================================================
TEST_USER_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


# ======================================================
# Engine & Session
# ======================================================
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ======================================================
# DB Session Fixture
# ======================================================
@pytest.fixture(scope="function")
def db() -> Session:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ======================================================
# Middleware FIX IP (CLAVE 🔑)
# ======================================================
class FixedClientIPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request.scope["client"] = ("127.0.0.1", 1234)
        return await call_next(request)


# ======================================================
# Client Fixture
# ======================================================
@pytest.fixture(scope="function")
def client(db: Session):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.add_middleware(FixedClientIPMiddleware)

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
    app.user_middleware.clear()
    app.middleware_stack = None


# ======================================================
# User Fixture
# ======================================================
@pytest.fixture(scope="function")
def user(db: Session) -> Users:
    user = db.get(Users, TEST_USER_ID)

    if not user:
        user = Users(
            user_id=TEST_USER_ID,
            email="test.user@example.com",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return user


@pytest.fixture
def user_id(user: Users):
    return user.user_id
