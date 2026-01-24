import pytest
from sqlalchemy.orm import Session

from app.repositories.audit_repository import AuditRepository
from app.models.af_audit_log import AuditLog
from app.models.af_projects import Project
from app.models.af_external_projects import AfExternalProject
from app.models.cat_terms import CatTerm
from app.models.cat_vocabularies import CatVocabulary
from app.models.users import Users


# ---------------------------------------------------------
# Repository
# ---------------------------------------------------------

@pytest.fixture
def audit_repo():
    return AuditRepository()


# ---------------------------------------------------------
# Catálogos (leídos desde BD, no creados)
# ---------------------------------------------------------

@pytest.fixture
def user_status_term(db: Session):
    vocab = (
        db.query(CatVocabulary)
        .filter(CatVocabulary.vocabulary_code == "USER_STATUS")
        .first()
    )
    assert vocab is not None, "❌ Falta vocabulario USER_STATUS"

    term = (
        db.query(CatTerm)
        .filter(
            CatTerm.code == "ACTIVE",
            CatTerm.vocabulary_id == vocab.vocabulary_id
        )
        .first()
    )
    assert term is not None, "❌ Falta término USER_STATUS.ACTIVE"

    return term


@pytest.fixture
def project_status_term(db: Session):
    vocab = (
        db.query(CatVocabulary)
        .filter(CatVocabulary.vocabulary_code == "PROJECT_STATUS")
        .first()
    )
    assert vocab is not None, "❌ Falta vocabulario PROJECT_STATUS"

    term = (
        db.query(CatTerm)
        .filter(
            CatTerm.code == "ACTIVE",
            CatTerm.vocabulary_id == vocab.vocabulary_id
        )
        .first()
    )
    assert term is not None, "❌ Falta término PROJECT_STATUS.ACTIVE"

    return term


@pytest.fixture
def audit_action_terms(db: Session):
    vocab = (
        db.query(CatVocabulary)
        .filter(CatVocabulary.vocabulary_code == "AUDIT_ACTION")
        .first()
    )
    assert vocab is not None, "❌ Falta vocabulario AUDIT_ACTION"

    required_codes = {
        "AUTH_LOGIN_SUCCESS",
        "OTP_FAILED",
        "OTP_EXPIRED",
        "OTP_BLOCKED",
    }

    terms = (
        db.query(CatTerm)
        .filter(
            CatTerm.vocabulary_id == vocab.vocabulary_id,
            CatTerm.code.in_(required_codes)
        )
        .all()
    )

    found_codes = {t.code for t in terms}
    missing = required_codes - found_codes

    assert not missing, f"❌ Faltan términos AUDIT_ACTION: {missing}"

    return {t.code: t for t in terms}


# ---------------------------------------------------------
# Entidades base (leídas desde BD)
# ---------------------------------------------------------

@pytest.fixture
def test_user(db: Session):
    user = (
        db.query(Users)
        .filter(Users.email == "agrofusion2025@gmail.com")
        .first()
    )
    assert user is not None, "❌ No existe el usuario agrofusion2025@gmail.com"

    return user


@pytest.fixture
def project(db: Session):
    project = (
        db.query(Project)
        .filter(Project.code == "AGROFUSION")
        .first()
    )
    assert project is not None, "❌ No existe el proyecto AGROFUSION"

    return project


# ---------------------------------------------------------
# Tests
# ---------------------------------------------------------

def test_get_project_by_code(db: Session, audit_repo, project):
    result = audit_repo.get_project_by_code(db, code="AGROFUSION")

    assert result is not None
    assert result.af_project_id == project.af_project_id


def test_get_projectExt_by_code(db: Session, audit_repo):
    project = (
        db.query(AfExternalProject)
        .filter(AfExternalProject.instance_code == "DISRIEGO")
        .first()
    )
    assert project is not None, "❌ Falta proyecto externo DISRIEGO"

    result = audit_repo.get_projectExt_by_code(db, code="DISRIEGO")

    assert result is not None
    assert result.instance_code == "DISRIEGO"


def test_get_active_ext_pro(db: Session, audit_repo):
    result = audit_repo.get_active_ext_pro(db)

    assert result, "❌ No hay proyectos externos activos"

    for p in result:
        assert p.is_active is True


def test_get_action_term_id_not_found(db: Session, audit_repo):
    with pytest.raises(RuntimeError):
        audit_repo._get_action_term_id(db, action_code="INVALID_ACTION")


def test_log_login_event_success(
    db: Session,
    audit_repo,
    project,
    audit_action_terms
):
    audit_repo.log_login_event(
        db=db,
        action_code="AUTH_LOGIN_SUCCESS",
        outcome="success",
        project_id=project.af_project_id,
        email="user@test.com",
        ip="127.0.0.1",
        user_agent="pytest"
    )

    db.commit()

    log = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .first()
    )

    assert log is not None
    assert log.action_code == "AUTH_LOGIN_SUCCESS"
    assert log.outcome == "success"
    assert log.project_id == project.af_project_id


def test_log_event_generic(
    db: Session,
    audit_repo,
    project,
    audit_action_terms
):
    audit_repo.log_event(
        db=db,
        action_code="AUTH_LOGIN_SUCCESS",
        outcome="success",
        module_code="AUTH",
        project_id=project.af_project_id,
        metadata={"key": "value"}
    )

    db.commit()

    log = db.query(AuditLog).first()

    assert log is not None
    assert log.module_code == "AUTH"


def test_opt_failed(
    db: Session,
    audit_repo,
    project,
    audit_action_terms,
    test_user
):
    audit_repo.opt_failed(
        db=db,
        user=test_user,
        project=project,
        ip="127.0.0.1",
        user_agent="pytest",
        reason="invalid_code",
        attempts_count=3
    )

    db.commit()

    log = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .first()
    )

    assert log is not None
    assert log.action_code == "OTP_FAILED"
    assert log.outcome == "failed"
