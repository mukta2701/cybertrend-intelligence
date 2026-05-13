from __future__ import annotations

from typing import Iterable, Optional

import boto3

from cybertrend.models import RenderedEmail


class SESEmailSender:
    def __init__(
        self,
        from_email: str,
        configuration_set: Optional[str] = None,
        client=None,
        region_name: Optional[str] = None,
    ):
        self.from_email = from_email
        self.configuration_set = configuration_set
        self.client = client or boto3.client("sesv2", region_name=region_name)

    def send(self, message: RenderedEmail, recipients: Iterable[str]) -> dict:
        payload = {
            "FromEmailAddress": self.from_email,
            "Destination": {"ToAddresses": list(recipients)},
            "Content": {
                "Simple": {
                    "Subject": {"Data": message.subject},
                    "Body": {
                        "Html": {"Data": message.html},
                        "Text": {"Data": message.text},
                    },
                }
            },
        }
        if self.configuration_set:
            payload["ConfigurationSetName"] = self.configuration_set
        return self.client.send_email(**payload)
