import pytest
from unittest.mock import patch
from sqlalchemy.orm import Session

from app.repositories.email_repository import EmailRepository
from app.models.af_email_templates import AfEmailTemplate
from app.models.af_email_queue import AfEmailQueue
from app.models.af_email_send_log import EmailSendLog


# ---------------------------------------------------------
# Fixtures base
# ---------------------------------------------------------

@pytest.fixture
def email_repo():
    return EmailRepository()


@pytest.fixture
def user():
    return type(
        "User",
        (),
        {
            "email": "alejab2302@gmail.com",
            "name": "Usuario Test",
        },
    )()


@pytest.fixture
def otp_template(db: Session):
    template = (
        db.query(AfEmailTemplate)
        .filter(AfEmailTemplate.template_code == "otp_2fa")
        .first()
    )

    if not template:
        template = AfEmailTemplate(
            template_code="otp_2fa",
            template_name="OTP 2FA",
            subject_template="Tu código OTP",
            body_html_template="<p>{{ otp_code }}</p>",
            body_text_template="Código: {{ otp_code }}",
            is_active=True,
        )
        db.add(template)
        db.commit()

    return template


@pytest.fixture
def reset_template(db: Session):
    template = (
        db.query(AfEmailTemplate)
        .filter(AfEmailTemplate.template_code == "reset_password")
        .first()
    )

    if not template:
        template = AfEmailTemplate(
            template_code="reset_password",
            template_name="Reset Password",
            subject_template="Resetear contraseña",
            body_html_template="<p>{{ reset_password_url }}</p>",
            body_text_template="Reset: {{ reset_password_url }}",
            is_active=True,
        )
        db.add(template)
        db.commit()

    return template


# ---------------------------------------------------------
# get_email_template
# ---------------------------------------------------------

def test_get_email_template_success(db: Session, email_repo, otp_template):
    template = email_repo.get_email_template(db, "otp_2fa")

    assert template.template_code == "otp_2fa"
    assert template.is_active is True


def test_get_email_template_not_found(db: Session, email_repo):
    with pytest.raises(RuntimeError, match="Email template not found"):
        email_repo.get_email_template(db, "invalid_template")


# ---------------------------------------------------------
# enqueue_otp_email
# ---------------------------------------------------------

@patch("app.repositories.email_repository.send_templated_email")
@patch("app.repositories.email_repository.render_template")
def test_enqueue_otp_email_success(
    mock_render,
    mock_send,
    db: Session,
    email_repo,
    user,
    otp_template,
):
    mock_render.side_effect = lambda tpl, data: "rendered"
    mock_send.return_value = "SMTP OK"

    email_queue = email_repo.enqueue_otp_email(
        db=db,
        user=user,
        otp_code="123456",
        ip="127.0.0.1",
    )

    assert email_queue.status == "sent"
    assert email_queue.attempts == 1

    queue_db = db.query(AfEmailQueue).first()
    assert queue_db is not None
    assert queue_db.recipient_email == user.email

    log = db.query(EmailSendLog).first()
    assert log is not None
    assert log.status == "sent"



# ---------------------------------------------------------
# enqueue_reset_pass_email
# ---------------------------------------------------------

@patch("app.repositories.email_repository.send_templated_email")
@patch("app.repositories.email_repository.render_template")
def test_enqueue_reset_password_email_success(
    mock_render,
    mock_send,
    db: Session,
    email_repo,
    user,
    reset_template,
):
    mock_render.side_effect = lambda tpl, data: "rendered"
    mock_send.return_value = "SMTP OK"

    email_queue = email_repo.enqueue_reset_pass_email(
        db=db,
        user=user,
        token="reset-token",
        tokens={"lang": "es"},
        ip="127.0.0.1",
    )

    assert email_queue.status == "sent"
    assert email_queue.attempts == 1

    log = db.query(EmailSendLog).first()
    assert log is not None
    assert log.status == "sent"
