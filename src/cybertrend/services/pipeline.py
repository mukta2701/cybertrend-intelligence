from __future__ import annotations

import os
import time
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy.orm import scoped_session

from cybertrend.config import Settings
from cybertrend.connectors.tenable import TenableVPRClient
from cybertrend.db.repository import Repository
from cybertrend.db.session import make_session_factory
from cybertrend.email.render import render_daily_digest, render_immediate_alert
from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.models import DigestPayload, DigestSection, SourcePolicy, TrendItem
from cybertrend.queue import SQSQueue
from cybertrend.services.ingestion import IngestionService
from cybertrend.summaries import HybridSummaryProvider

DEFAULT_RSS_FEEDS = {
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
    "sans_isc": "https://isc.sans.edu/rssfeed_full.xml",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "securityweek": "https://www.securityweek.com/feed/",
    "tenable": "https://www.tenable.com/security/research/feed",
    "reddit_pwnhub": "https://www.reddit.com/r/pwnhub/.rss",
}

DEFAULT_NVD_JOBS = [
    {"source_type": "nvd", "source_name": "nvd", "hours_back": 24},
]


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
        email_sender = None
        if settings.smtp_user and settings.smtp_password:
            email_sender = SMTPEmailSender(
                host=settings.smtp_host,
                port=settings.smtp_port,
                user=settings.smtp_user,
                password=settings.smtp_password,
                from_email=settings.email_from or settings.smtp_user,
                timeout_seconds=settings.smtp_timeout_seconds,
            )
        llm_provider = None
        if settings.llm_provider == "openai" and settings.llm_api_key:
            from cybertrend.summaries_openai import OpenAISummaryProvider

            llm_provider = OpenAISummaryProvider(api_key=settings.llm_api_key)
        summarizer = HybridSummaryProvider(llm_provider=llm_provider)
        ingestion = IngestionService(
            repository=repository,
            alert_queue=alert_queue,
            tenable_client=TenableVPRClient(
                access_key=settings.tenable_access_key,
                secret_key=settings.tenable_secret_key,
            ),
            summarizer=summarizer,
            max_items_per_source=settings.max_items_per_source,
            max_nvd_items=settings.max_nvd_items,
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
        for name, url in DEFAULT_RSS_FEEDS.items():
            jobs.append(
                {
                    "source_type": "rss",
                    "source_name": name,
                    "url": url,
                    "requested_at": requested_at,
                }
            )
        for nvd_job in DEFAULT_NVD_JOBS:
            jobs.append({**nvd_job, "requested_at": requested_at})
        processed_jobs = 0
        stored_items = 0
        failed_jobs: List[Dict[str, Any]] = []
        source_stats: List[Dict[str, Any]] = []
        if self.queue:
            for job in jobs:
                self.queue.enqueue(job)
                source_stats.append(
                    {
                        "source_type": job.get("source_type"),
                        "source_name": job.get("source_name"),
                        "queued": True,
                    }
                )
        elif self.ingestion_service:
            for job in jobs:
                started = time.perf_counter()
                stat: Dict[str, Any] = {
                    "source_type": job.get("source_type"),
                    "source_name": job.get("source_name"),
                    "success": False,
                }
                try:
                    stored = self.ingestion_service.process_job(job)
                    stored_items += stored
                    processed_jobs += 1
                    stat.update(self._ingestion_stats_payload(stored))
                    stat["success"] = True
                except Exception as exc:
                    failed_jobs.append(
                        {
                            "source_type": job.get("source_type"),
                            "source_name": job.get("source_name"),
                            "community": job.get("community"),
                            "error": str(exc),
                        }
                    )
                    stat["error"] = str(exc)
                finally:
                    stat["elapsed_seconds"] = round(time.perf_counter() - started, 3)
                    source_stats.append(stat)
        result = {
            "run_id": run_id,
            "queued_jobs": len(jobs),
            "processed_jobs": processed_jobs,
            "stored_items": stored_items,
            "failed_jobs": failed_jobs,
            "source_stats": source_stats,
        }
        if not self.queue and self.ingestion_service:
            result["alerts_sent"] = self._send_pending_critical_alerts()
        return result

    def _ingestion_stats_payload(self, stored_items: int) -> Dict[str, Any]:
        stats = getattr(self.ingestion_service, "last_stats", None)
        if stats is None:
            return {"stored_items": stored_items}
        if is_dataclass(stats):
            payload = asdict(stats)
        elif isinstance(stats, dict):
            payload = dict(stats)
        else:
            payload = dict(getattr(stats, "__dict__", {}))
        payload.setdefault("stored_items", stored_items)
        return payload

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
            stored = self.repository.get_digest(digest_date)
            if stored:
                return stored
            if getattr(self.repository, "build_digest_from_items", None):
                return self.repository.build_digest_from_items(digest_date)
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(name="Critical Threats", severity="Critical", items=[]),
                DigestSection(name="High Priority", severity="High", items=[]),
                DigestSection(name="Medium Risk", severity="Medium", items=[]),
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
        if not recipients:
            return False
        self.email_sender.send(render_immediate_alert(item), recipients)
        self.repository.record_alert_delivery(item_id, "immediate")
        return True

    def send_daily_digest(self, digest_date: date) -> Dict[str, Any]:
        payload = self.get_digest(digest_date)
        if self.repository:
            self.repository.save_digest(payload)          # persist first, sent_at=None
        sent = False
        if self.email_sender and self.settings and self.settings.digest_recipients:
            try:
                self.email_sender.send(
                    render_daily_digest(payload), self.settings.digest_recipients
                )
                sent = True
                if self.repository:
                    self.repository.save_digest(payload, sent_at=datetime.now(timezone.utc))
            except Exception:
                pass
        return {"digest_date": digest_date.isoformat(), "sent": sent}

    def _send_pending_critical_alerts(self) -> int:
        if not self.repository or not self.email_sender:
            return 0
        today = datetime.now(timezone.utc).date()
        items = self.repository.get_items_by_ingestion_date(today)
        sent = 0
        for item in items:
            if item.severity_label == "Critical" and self.send_immediate_alert(item.item_id):
                sent += 1
        return sent

    def refresh_source_quality(self) -> Dict[str, Any]:
        if not self.repository:
            return {"updated_sources": 0}
        return self.repository.refresh_source_quality()
