from __future__ import annotations

import os
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy.orm import scoped_session

from cybertrend.config import Settings
from cybertrend.connectors.reddit import RedditClient
from cybertrend.connectors.tenable import TenableVPRClient
from cybertrend.db.repository import Repository
from cybertrend.db.session import make_session_factory
from cybertrend.email.render import render_daily_digest, render_immediate_alert
from cybertrend.email.ses import SESEmailSender
from cybertrend.models import DigestPayload, DigestSection, SourcePolicy, TrendItem
from cybertrend.queue import SQSQueue
from cybertrend.services.ingestion import IngestionService

DEFAULT_REDDIT_COMMUNITIES = ["netsec", "cybersecurity", "threatintel", "blueteamsec", "Malware"]
DEFAULT_RSS_FEEDS = {
    "tenable": "https://www.tenable.com/security/research/feed",
}


class PipelineService:
    def __init__(
        self,
        repository=None,
        queue=None,
        alert_queue=None,
        email_sender=None,
        ingestion_service=None,
        settings: Optional[Settings] = None,
    ):
        self.repository = repository
        self.queue = queue
        self.alert_queue = alert_queue
        self.email_sender = email_sender
        self.ingestion_service = ingestion_service
        self.settings = settings

    @classmethod
    def from_settings(cls, settings: Settings) -> "PipelineService":
        session_factory = make_session_factory(settings.database_url)
        repository = Repository(scoped_session(session_factory))
        source_queue = (
            SQSQueue(os.environ["SOURCE_QUEUE_URL"], region_name=settings.aws_region)
            if os.environ.get("SOURCE_QUEUE_URL")
            else None
        )
        alert_queue = (
            SQSQueue(os.environ["ALERT_QUEUE_URL"], region_name=settings.aws_region)
            if os.environ.get("ALERT_QUEUE_URL")
            else None
        )
        email_sender = SESEmailSender(
            from_email=settings.ses_from_email,
            configuration_set=settings.ses_configuration_set,
            region_name=settings.aws_region,
        )
        reddit_client = None
        if settings.reddit_client_id and settings.reddit_client_secret:
            reddit_client = RedditClient(
                client_id=settings.reddit_client_id,
                client_secret=settings.reddit_client_secret,
                user_agent=settings.reddit_user_agent,
            )
        ingestion = IngestionService(
            repository=repository,
            alert_queue=alert_queue,
            reddit_client=reddit_client,
            tenable_client=TenableVPRClient(
                access_key=settings.tenable_access_key,
                secret_key=settings.tenable_secret_key,
            ),
        )
        return cls(
            repository=repository,
            queue=source_queue,
            alert_queue=alert_queue,
            email_sender=email_sender,
            ingestion_service=ingestion,
            settings=settings,
        )

    def trigger_manual_run(self) -> Dict[str, Any]:
        run_id = f"manual-{uuid4()}"
        jobs: List[Dict[str, Any]] = []
        requested_at = datetime.now(timezone.utc).isoformat()
        for community in DEFAULT_REDDIT_COMMUNITIES:
            jobs.append(
                {
                    "source_type": "reddit",
                    "source_name": "reddit",
                    "community": community,
                    "requested_at": requested_at,
                }
            )
        for name, url in DEFAULT_RSS_FEEDS.items():
            jobs.append(
                {
                    "source_type": "rss",
                    "source_name": name,
                    "url": url,
                    "requested_at": requested_at,
                }
            )
        processed_jobs = 0
        stored_items = 0
        failed_jobs: List[Dict[str, Any]] = []
        if self.queue:
            for job in jobs:
                self.queue.enqueue(job)
        elif self.ingestion_service:
            for job in jobs:
                try:
                    stored_items += self.ingestion_service.process_job(job)
                    processed_jobs += 1
                except Exception as exc:
                    failed_jobs.append(
                        {
                            "source_type": job.get("source_type"),
                            "source_name": job.get("source_name"),
                            "community": job.get("community"),
                            "error": str(exc),
                        }
                    )
        return {
            "run_id": run_id,
            "queued_jobs": len(jobs),
            "processed_jobs": processed_jobs,
            "stored_items": stored_items,
            "failed_jobs": failed_jobs,
        }

    def process_source_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        if self.ingestion_service:
            return {"stored": self.ingestion_service.process_job(job), "job": job}
        if not self.repository or not getattr(self.repository, "process_source_job", None):
            return {"stored": 0, "job": job}
        return self.repository.process_source_job(job)

    def list_items(
        self,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.repository:
            return {"items": [], "next_cursor": None}
        return self.repository.list_items(
            severity=severity, source=source, since=since, limit=limit, cursor=cursor
        )

    def get_digest(self, digest_date: date) -> DigestPayload:
        if self.repository:
            payload = self.repository.get_digest(digest_date)
            if payload:
                return payload
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(name="Critical - Act Now", severity="Critical", items=[]),
                DigestSection(name="High - Prioritize This Week", severity="High", items=[]),
                DigestSection(name="Medium - Track", severity="Medium", items=[]),
            ],
        )

    def get_source_health(self) -> Dict[str, Any]:
        if not self.repository:
            return {"sources": []}
        return {"sources": self.repository.get_source_health()}

    def update_source_policy(self, policy: SourcePolicy) -> SourcePolicy:
        if self.repository:
            self.repository.update_source_policy(policy)
        return policy

    def explain_score(self, item_id: str) -> Dict[str, Any]:
        if not self.repository:
            return {"item_id": item_id, "score_breakdown": None}
        return self.repository.explain_score(item_id)

    def send_immediate_alert(self, item_id: str) -> bool:
        if not self.repository or not self.email_sender:
            return False
        item: Optional[TrendItem] = self.repository.get_item(item_id)
        if not item or item.severity_label != "Critical":
            return False
        if self.repository.alert_already_sent(item_id, "immediate"):
            return False
        recipients = self.settings.alert_recipients if self.settings else []
        self.email_sender.send(render_immediate_alert(item), recipients)
        self.repository.record_alert_delivery(item_id, "immediate")
        return True

    def send_daily_digest(self, digest_date: date) -> Dict[str, Any]:
        payload = self.get_digest(digest_date)
        if self.email_sender and self.settings and self.settings.digest_recipients:
            self.email_sender.send(render_daily_digest(payload), self.settings.digest_recipients)
        return {"digest_date": digest_date.isoformat(), "sent": bool(self.email_sender)}

    def refresh_source_quality(self) -> Dict[str, Any]:
        if not self.repository:
            return {"updated_sources": 0}
        return self.repository.refresh_source_quality()
