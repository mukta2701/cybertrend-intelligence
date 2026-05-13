from unittest.mock import MagicMock, patch

from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.models import RenderedEmail

SMTP_PASSWORD_PLACEHOLDER = "placeholder"


def _message():
    return RenderedEmail(subject="Test Subject", html="<p>Test</p>", text="Test")


def test_smtp_sender_sends_to_recipients():
    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        sender = SMTPEmailSender(
            host="smtp.gmail.com",
            port=587,
            user="test@gmail.com",
            password=SMTP_PASSWORD_PLACEHOLDER,
            from_email="test@gmail.com",
        )
        sender.send(_message(), ["analyst@example.com"])

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("test@gmail.com", SMTP_PASSWORD_PLACEHOLDER)
        mock_smtp.sendmail.assert_called_once()
        args = mock_smtp.sendmail.call_args[0]
        assert args[0] == "test@gmail.com"
        assert args[1] == ["analyst@example.com"]


def test_smtp_sender_skips_send_with_no_recipients():
    with patch("smtplib.SMTP") as mock_smtp_class:
        sender = SMTPEmailSender(
            host="smtp.gmail.com",
            port=587,
            user="test@gmail.com",
            password=SMTP_PASSWORD_PLACEHOLDER,
            from_email="test@gmail.com",
        )
        sender.send(_message(), [])
        mock_smtp_class.assert_not_called()
