from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from app.repositories.users_repository import UsersRepository
from app.models.users import Users
from datetime import datetime, timedelta, timezone
from app.models.af_login_attempts import LoginAttempt
from app.models.af_password_history import PasswordHistory
from app.models.af_password_polices import PasswordPolicy
from app.core.security import ACCOUNT_LOCK_DURATION
TEST_USER_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TEST_EMAIL = "agrofusion2025@gmail.com"
@pytest.fixture
def users_repo():
    return UsersRepository()


@pytest.fixture
def user(db: Session) -> Users:
    user = db.get(Users, TEST_USER_ID)

    if not user:
        user = Users(
            user_id=TEST_USER_ID,
            email=TEST_EMAIL,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return user
def test_get_by_email_returns_user(
    db: Session,
    users_repo,
    user,
):
    result = users_repo.get_by_email(db, TEST_EMAIL)

    assert result is not None
    assert result.user_id == user.user_id


def test_get_by_email_returns_none_if_not_found(
    db: Session,
    users_repo,
):
    result = users_repo.get_by_email(db, "no.existe@test.com")
    assert result is None
def test_is_account_lock_expired_returns_false_if_not_locked(
    users_repo,
):
    assert users_repo.is_account_lock_expired(None) is False


def test_is_account_lock_expired_returns_false_if_still_locked(
    users_repo,
):
    locked_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert users_repo.is_account_lock_expired(locked_at) is False


def test_is_account_lock_expired_returns_true_if_expired(
    users_repo,
):
    locked_at = datetime.now(timezone.utc) - ACCOUNT_LOCK_DURATION - timedelta(seconds=1)
    assert users_repo.is_account_lock_expired(locked_at) is True
def test_register_login_attempt_with_existing_user(
    db: Session,
    users_repo,
    user,
):
    users_repo.register_login_attempt(
        db,
        user=user,
        email=user.email,
        success=False,
        reason="INVALID_PASSWORD",
        ip="127.0.0.1"
    )

    attempt = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.email == user.email)
        .order_by(LoginAttempt.at.desc())
        .first()
    )

    assert attempt is not None
    assert attempt.user_id == user.user_id
    assert attempt.success is False


def test_register_login_attempt_without_user(
    db: Session,
    users_repo,
):
    email = "ghost@test.com"

    users_repo.register_login_attempt(
        db,
        user=None,
        email=email,
        success=False,
        reason="USER_NOT_FOUND",
        ip="127.0.0.1",
    )

    attempt = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.email == email)
        .first()
    )

    assert attempt is not None
    assert attempt.user_id is None
def test_add_password_history_creates_record(
    db: Session,
    users_repo,
    user,
):
    history = users_repo.add_password_history(
        db,
        user_id=user.user_id,
        password_hash="hashed-password",
        changed_by=user.user_id,
        change_reason="RESET",
        ip="127.0.0.1",
        user_agent="pytest",
    )

    db.commit()
    db.refresh(history)

    assert history.user_id == user.user_id
    assert history.password_hash == "hashed-password"
    assert history.change_reason == "RESET"
def test_get_active_policy_returns_latest_active(
    db: Session,
    users_repo,
):
    old_policy = PasswordPolicy(
        min_length=8,
        policy_name="default_lazy", 
        max_length=64,
        is_active=True,
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )

    new_policy = PasswordPolicy(
        min_length=12,
        max_length=64,
        policy_name="new_strong",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    db.add_all([old_policy, new_policy])
    db.commit()

    policy = users_repo.get_active_policy(db)

    assert policy.min_length == 12


def test_get_active_policy_raises_if_none_active(
    db: Session,
    users_repo,
):
    db.query(PasswordPolicy).delete()
    db.commit()

    with pytest.raises(RuntimeError, match="No active password policy found"):
        users_repo.get_active_policy(db)
