from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any, Dict

from mangum import Mangum

from cybertrend.api import create_app
from cybertrend.config import get_settings
from cybertrend.services.pipeline import PipelineService

settings = get_settings()
pipeline = PipelineService.from_settings(settings)
app = create_app(pipeline=pipeline, api_key=settings.api_key)
api_handler = Mangum(app)


def collector_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    return pipeline.trigger_manual_run()


def ingestion_worker_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    failures = []
    processed = 0
    for record in event.get("Records", []):
        try:
            job = json.loads(record.get("body") or "{}")
            pipeline.process_source_job(job)
            processed += 1
        except Exception:
            failures.append({"itemIdentifier": record.get("messageId")})
    return {"processed": processed, "batchItemFailures": failures}


def alert_worker_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    sent = 0
    for record in event.get("Records", []):
        payload = json.loads(record.get("body") or "{}")
        if pipeline.send_immediate_alert(payload["item_id"]):
            sent += 1
    return {"sent": sent}


def digest_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    digest_date = (
        date.fromisoformat(event["date"])
        if isinstance(event, dict) and event.get("date")
        else today
    )
    return pipeline.send_daily_digest(digest_date)


def source_quality_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    return pipeline.refresh_source_quality()
