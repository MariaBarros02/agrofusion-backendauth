from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from app.repositories.auth_repository import AuthRepository
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.models.af_password_reset_tokens import PasswordResetToken
from app.models.users import Users
from app.core.config import settings
import hashlib

TEST_USER_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TEST_EMAIL = "agrofusion2025@gmail.com"
TEST_SESSION_ID = UUID("b4e987e9-0c1e-4369-9fb7-b3d639583fd5")

@pytest.fixture
def auth_repo():
    return AuthRepository()


@pytest.fixture
def user(db: Session) -> Users:
    user = db.get(Users, TEST_USER_ID)

    if not user:
        user = Users(
            id=TEST_USER_ID,
            email=TEST_EMAIL,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return user

def test_create_session_persists_session(
    db: Session,
    auth_repo,
    user,
):
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    session = auth_repo.create_session(
        db,
        user_id=user.user_id,
        expires_at=expires_at,
        ip="127.0.0.1",
        user_agent="pytest",
    )

    db.commit()
    db.refresh(session)

    assert session.user_id == user.user_id
    assert session.expires_at == expires_at
    assert session.terminated_at is None

def test_create_tokens_creates_access_and_refresh(
    db: Session,
    auth_repo,
    user,
):
    session = AuthSession(
        user_id=user.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ip="127.0.0.1",
        user_agent="pytest",
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    token = auth_repo.create_tokens(
        db,
        session_id=session.sso_session_id,
        access_token="access.jwt.token",
        refresh_token="refresh.token",
        access_expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        refresh_expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )

    db.commit()
    db.refresh(token)

    assert token.sso_session_id == session.sso_session_id
    assert token.access_token == "access.jwt.token"
    
def test_revoke_token_session_marks_tokens_revoked(
    db: Session,
    auth_repo,
    user,
):
    session = AuthSession(
        user_id=user.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ip="127.0.0.1",
        user_agent="pytest",
    )
    token = AuthToken(
        sso_session_id=session.sso_session_id,
        access_token="access",
        refresh_token="refresh",
        access_expires_at=datetime.now(timezone.utc),
        refresh_expires_at=datetime.now(timezone.utc),
    )

    db.add_all([session, token])
    db.commit()

    auth_repo.revoke_token_session(
        db,
        session_id=session.sso_session_id,
        reason="LOGOUT",
    )

    db.commit()
    db.refresh(token)

    assert token.revoked_at is not None
    assert token.revoked_reason == "LOGOUT"

def test_revoke_by_session_returns_count(
    db: Session,
    auth_repo,
    user,
):
    session = AuthSession(
        user_id=user.user_id,
        expires_at=datetime.now(timezone.utc),
        ip="127.0.0.1",
        user_agent="pytest",
    )

    token1 = AuthToken(
        sso_session_id=session.sso_session_id,
        access_token="a1",
        refresh_token="r1",
        access_expires_at=datetime.now(timezone.utc),
        refresh_expires_at=datetime.now(timezone.utc),
    )

    token2 = AuthToken(
        sso_session_id=session.sso_session_id,
        access_token="a2",
        refresh_token="r2",
        access_expires_at=datetime.now(timezone.utc),
        refresh_expires_at=datetime.now(timezone.utc),
    )

    db.add_all([session, token1, token2])
    db.commit()

    count = auth_repo.revoke_by_session(
        db,
        session_id=session.sso_session_id,
        reason="SECURITY",
    )

    assert count == 2

def test_terminate_session_sets_terminated_at(
    db: Session,
    auth_repo,
    user,
):
    session = AuthSession(
        user_id=user.user_id,
        expires_at=datetime.now(timezone.utc),
        ip="127.0.0.1",
        user_agent="pytest",
    )

    db.add(session)
    db.commit()

    auth_repo.terminate_session(
        db,
        session_id=session.sso_session_id,
    )

    db.commit()
    db.refresh(session)

    assert session.terminated_at is not None

def test_gen_pass_reset_token_creates_hashed_token(
    db: Session,
    auth_repo,
    user,
):
    raw_token = auth_repo.gen_pass_reset_token(
        db,
        user,
        ip="127.0.0.1",
        user_agent="pytest",
    )

    assert raw_token is not None

    token_hash = hashlib.sha256(
        f"{raw_token}:{settings.secret_key}".encode("utf-8")
    ).hexdigest()

    stored = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .first()
    )

    assert stored is not None
    assert stored.user_id == user.user_id

def test_get_valid_pass_reset_token_returns_token(
    db: Session,
    auth_repo,
    user,
):
    raw_token = auth_repo.gen_pass_reset_token(db, user)

    token = auth_repo.get_valid_pass_reset_token(db, raw_token)

    assert token is not None
    assert token.user_id == user.user_id


def test_get_valid_pass_reset_token_returns_none_if_invalid(
    db: Session,
    auth_repo,
):
    assert auth_repo.get_valid_pass_reset_token(db, "invalid") is None

