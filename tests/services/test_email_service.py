import pytest
from unittest.mock import MagicMock, patch
from email.mime.multipart import MIMEMultipart

from app.services.email_service import send_templated_email
from app.core.config import settings


@patch("app.services.email_service.smtplib.SMTP")
def test_send_templated_email_success(mock_smtp):
    # Arrange
    smtp_instance = MagicMock()
    mock_smtp.return_value.__enter__.return_value = smtp_instance
    smtp_instance.send_message.return_value = {}

    # Act
    response = send_templated_email(
        to_email="user@example.com",
        subject="Test Subject",
        body_text="Texto plano",
        body_html="<p>HTML</p>",
    )

    # Assert
    mock_smtp.assert_called_once_with(
        settings.smtp_host,
        settings.smtp_port,
    )

    smtp_instance.starttls.assert_called_once()
    smtp_instance.login.assert_called_once_with(
        settings.smtp_user,
        settings.smtp_password,
    )
    smtp_instance.send_message.assert_called_once()

    sent_msg = smtp_instance.send_message.call_args[0][0]
    assert isinstance(sent_msg, MIMEMultipart)
    assert sent_msg["To"] == "user@example.com"
    assert sent_msg["Subject"] == "Test Subject"
    assert settings.smtp_user in sent_msg["From"]

    payloads = sent_msg.get_payload()
    assert payloads[0].get_payload(decode=True)
    assert payloads[1].get_payload(decode=True)

    assert response == "{}"


@patch("app.services.email_service.smtplib.SMTP")
def test_send_templated_email_smtp_error(mock_smtp):
    smtp_instance = MagicMock()
    mock_smtp.return_value.__enter__.return_value = smtp_instance
    smtp_instance.send_message.side_effect = Exception("SMTP failed")

    with pytest.raises(Exception, match="SMTP failed"):
        send_templated_email(
            to_email="user@example.com",
            subject="Error test",
            body_text="Texto",
            body_html="<p>Error</p>",
        )
