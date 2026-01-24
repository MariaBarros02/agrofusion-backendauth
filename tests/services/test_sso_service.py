import pytest
from types import SimpleNamespace
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import HTTPException
from app.services.sso_service import SsoService


def test_generate_sso_token_success(mocker):
    # --------------------------------------------------
    # Arrange
    # --------------------------------------------------
    db = mocker.Mock()

    user = SimpleNamespace(
        user_id=uuid4(),
        email="user@test.com"
    )

    session = SimpleNamespace(sso_session_id=uuid4())
    token = SimpleNamespace()

    project = SimpleNamespace(
        external_project_id=uuid4(),
        project_code="DISRIEGO"
    )

    audit_repo_mock = mocker.Mock()
    audit_repo_mock.get_projectExt_by_code.return_value = project

    mocker.patch(
        "app.services.sso_service.AuditRepository",
        return_value=audit_repo_mock
    )

    jwt_encode_mock = mocker.patch(
        "app.services.sso_service.jwt.encode",
        return_value="signed.jwt.token"
    )

    service = SsoService()

    # --------------------------------------------------
    # Act
    # --------------------------------------------------
    result = service.generate_sso_token(
        db=db,
        user=user,
        session=session,
        token=token,
        project_code="DISRIEGO",
        ip="127.0.0.1",
        user_agent="pytest"
    )

    # --------------------------------------------------
    # Assert
    # --------------------------------------------------
    assert result["sso_token"] == "signed.jwt.token"

    jwt_encode_mock.assert_called_once()
    payload = jwt_encode_mock.call_args[0][0]

    assert payload["iss"] == "agrofusion-auth"
    assert payload["aud"] == "EXT_APP"
    assert payload["sub"] == str(user.user_id)
    assert payload["email"] == user.email
    assert payload["exp"] > payload["iat"]

    audit_repo_mock.log_event.assert_called_once()
