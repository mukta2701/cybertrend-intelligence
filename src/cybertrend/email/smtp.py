from __future__ import annotations

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable

from cybertrend.models import RenderedEmail


class SMTPEmailSender:
    def __init__(self, host: str, port: int, user: str, password: str, from_email: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_email = from_email

    def send(self, message: RenderedEmail, recipients: Iterable[str]) -> None:
        recipient_list = list(recipients)
        if not recipient_list:
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = message.subject
        msg["From"] = self.from_email
        msg["To"] = ", ".join(recipient_list)
        msg.attach(MIMEText(message.text, "plain"))
        msg.attach(MIMEText(message.html, "html"))
        tls_context = ssl.create_default_context()
        with smtplib.SMTP(self.host, self.port) as smtp:
            smtp.starttls(context=tls_context)
            smtp.login(self.user, self.password)
            smtp.sendmail(self.from_email, recipient_list, msg.as_string())
