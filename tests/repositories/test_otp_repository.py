from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from app.repositories.otp_repository import OtpRepository
from app.models.af_otp_codes import AfOtpCode
from app.utils.otp import verify_otp_code


# ---------------------------------------------------------
# CONSTANTES FIJAS (NADA ALEATORIO)
# ---------------------------------------------------------
TEST_USER_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


# ---------------------------------------------------------
# Repo
# ---------------------------------------------------------
@pytest.fixture
def otp_repo():
    return OtpRepository()


@pytest.fixture
def user_id():
    return TEST_USER_ID


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def create_otp(
    db: Session,
    *,
    user_id,
    purpose="login",
    created_at=None,
    expires_at=None,
    used_at=None,
):
    otp = AfOtpCode(
        user_id=user_id,
        otp_hash="dummy_hash",
        purpose=purpose,
        created_at=created_at or datetime.now(timezone.utc),
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(minutes=5),
        used_at=used_at,
        failed_attempts=0,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)
    return otp


# ---------------------------------------------------------
# Tests: inv_active_otps
# ---------------------------------------------------------
def test_inv_active_otps_invalidates_only_active(
    db: Session,
    otp_repo,
    user_id,
):
    now = datetime.now(timezone.utc)

    active = create_otp(
        db,
        user_id=user_id,
        expires_at=now + timedelta(minutes=5),
    )

    expired = create_otp(
        db,
        user_id=user_id,
        expires_at=now - timedelta(minutes=1),
    )

    used = create_otp(
        db,
        user_id=user_id,
        expires_at=now + timedelta(minutes=5),
        used_at=now,
    )

    otp_repo.inv_active_otps(db, user_id, purpose="login")
    db.commit()

    db.refresh(active)
    db.refresh(expired)
    db.refresh(used)

    assert active.expires_at <= now
    assert expired.expires_at < now
    assert used.used_at is not None


# ---------------------------------------------------------
# Tests: get_last_otp
# ---------------------------------------------------------
def test_get_last_otp_returns_most_recent(
    db: Session,
    otp_repo,
    user_id,
):
    old = create_otp(
        db,
        user_id=user_id,
        created_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )

    new = create_otp(
        db,
        user_id=user_id,
        created_at=datetime.now(timezone.utc),
    )

    result = otp_repo.get_last_otp(db, user_id, purpose="login")

    assert result is not None
    assert result.otp_id == new.otp_id


# ---------------------------------------------------------
# Tests: count_recent_otps
# ---------------------------------------------------------
def test_count_recent_otps_only_counts_inside_window(
    db: Session,
    otp_repo,
    user_id,
):
    create_otp(
        db,
        user_id=user_id,
        created_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    create_otp(
        db,
        user_id=user_id,
        created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )

    count = otp_repo.count_recent_otps(
        db,
        user_id=user_id,
        purpose="login",
        minutes=5,
    )

    assert count == 1


# ---------------------------------------------------------
# Tests: create_otp
# ---------------------------------------------------------
def test_create_otp_hashes_and_persists(
    db: Session,
    otp_repo,
    user_id,
):
    otp_code = "123456"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    otp = otp_repo.create_otp(
        db,
        user_id=user_id,
        otp_code=otp_code,
        purpose="login",
        expires_at=expires_at,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    db.commit()
    db.refresh(otp)

    assert otp.user_id == user_id
    assert otp.purpose == "login"
    assert otp.expires_at == expires_at
    assert otp.used_at is None
    assert otp.failed_attempts == 0

    assert otp.otp_hash != otp_code
    assert verify_otp_code(otp_code, otp.otp_hash)
