from __future__ import annotations

import json
from typing import Any, Dict

import boto3


class SQSQueue:
    def __init__(self, queue_url: str, client=None, region_name: str | None = None):
        self.queue_url = queue_url
        self.client = client or boto3.client("sqs", region_name=region_name)

    def enqueue(self, payload: Dict[str, Any]) -> dict:
        return self.client.send_message(
            QueueUrl=self.queue_url, MessageBody=json.dumps(payload, default=str)
        )
