from datetime import date, datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import cybertrend.services.pipeline as pipeline_module
from cybertrend.config import Settings
from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.models import DigestPayload, DigestSection, EngagementMetrics, SourceType, TrendItem
from cybertrend.services.pipeline import PipelineService
from cybertrend.summaries import HybridSummaryProvider


class FakeRepository:
    def __init__(self, items_by_date=None):
        self.saved_digests = []
        self.items_by_date = items_by_date or {}
        self.alert_deliveries = set()
        self.stored_items = {}

    def get_digest(self, digest_date):
        return None

    def build_digest_from_items(self, digest_date):
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(name="Critical Threats", severity="Critical", items=[]),
                DigestSection(name="High Priority",    severity="High",     items=[]),
                DigestSection(name="Medium Risk",      severity="Medium",   items=[]),
            ],
        )

    def save_digest(self, payload):
        self.saved_digests.append(payload)

    def get_items_by_ingestion_date(self, target_date):
        return self.items_by_date.get(target_date, [])

    def get_item(self, item_id):
        return self.stored_items.get(item_id)

    def alert_already_sent(self, item_id, delivery_type):
        return (item_id, delivery_type) in self.alert_deliveries

    def record_alert_delivery(self, item_id, delivery_type, provider_message_id=None):
        self.alert_deliveries.add((item_id, delivery_type))


class FakeEmailSender:
    def __init__(self):
        self.sent = []

    def send(self, message, recipients):
        self.sent.append((message, list(recipients)))


def _critical_item():
    return TrendItem(
        item_id="rss:test:critical",
        source_type=SourceType.RSS,
        source_name="thehackernews",
        title="Critical Vuln",
        url="https://example.com/crit",
        published_at=datetime(2026, 6, 2, 8, 0, tzinfo=timezone.utc),
        criticality_score=95,
        severity_label="Critical",
        engagement_metrics=EngagementMetrics(),
    )


class FakeIngestionService:
    def __init__(self):
        self.jobs = []
        self.last_stats = {
            "fetched_items": 3,
            "processed_items": 2,
            "stored_items": 2,
            "skipped_summaries": 1,
            "limited_items": 1,
        }

    def process_job(self, job):
        self.jobs.append(job)
        return 2


def test_manual_run_processes_all_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 9
    assert result["processed_jobs"] == 9
    assert result["stored_items"] == 18
    assert len(result["failed_jobs"]) == 0
    assert len(result["source_stats"]) == 9
    assert result["source_stats"][0]["stored_items"] == 2
    assert result["source_stats"][0]["skipped_summaries"] == 1
    assert result["source_stats"][0]["limited_items"] == 1
    assert result["source_stats"][0]["elapsed_seconds"] >= 0
    source_types = {job["source_type"] for job in ingestion.jobs}
    assert source_types == {"rss", "nvd"}


def test_from_settings_uses_local_smtp_and_openai_summarizer(monkeypatch):
    class FakeOpenAISummaryProvider:
        def __init__(self, api_key):
            self.api_key = api_key

    class FakeSESEmailSender:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    import cybertrend.summaries_openai as summaries_openai

    monkeypatch.setattr(pipeline_module, "make_session_factory", lambda database_url: object())
    monkeypatch.setattr(pipeline_module, "scoped_session", lambda session_factory: MagicMock())
    monkeypatch.setattr(pipeline_module, "Repository", lambda session: MagicMock())
    monkeypatch.setattr(pipeline_module, "SESEmailSender", FakeSESEmailSender, raising=False)
    monkeypatch.setattr(summaries_openai, "OpenAISummaryProvider", FakeOpenAISummaryProvider)

    settings = Settings(
        database_url="postgresql+psycopg://example:example@localhost/example",
        smtp_user="sender@gmail.com",
        smtp_password=uuid4().hex,
        smtp_timeout_seconds=12,
        email_from="alerts@example.com",
        llm_provider="openai",
        llm_api_key="sk-test",
        max_items_per_source=10,
        max_nvd_items=20,
    )

    service = PipelineService.from_settings(settings)

    assert isinstance(service.email_sender, SMTPEmailSender)
    assert service.email_sender.user == "sender@gmail.com"
    assert service.email_sender.from_email == "alerts@example.com"
    assert service.email_sender.timeout_seconds == 12
    assert service.ingestion_service.max_items_per_source == 10
    assert service.ingestion_service.max_nvd_items == 20
    assert isinstance(service.ingestion_service.summarizer, HybridSummaryProvider)
    assert isinstance(service.ingestion_service.summarizer.llm_provider, FakeOpenAISummaryProvider)
    assert service.ingestion_service.summarizer.llm_provider.api_key == "sk-test"


# ── new tests ──

def test_send_daily_digest_returns_sent_true_when_email_is_delivered():
    settings = Settings(
        database_url="postgresql+psycopg://x:x@localhost/x",
        digest_recipients="analyst@example.com",
    )
    pipeline = PipelineService(
        repository=FakeRepository(),
        email_sender=FakeEmailSender(),
        settings=settings,
    )

    result = pipeline.send_daily_digest(date(2026, 6, 2))

    assert result["sent"] is True


def test_send_daily_digest_returns_sent_false_when_no_recipients_configured():
    settings = Settings(
        database_url="postgresql+psycopg://x:x@localhost/x",
        digest_recipients="",
    )
    sender = FakeEmailSender()
    pipeline = PipelineService(
        repository=FakeRepository(),
        email_sender=sender,
        settings=settings,
    )

    result = pipeline.send_daily_digest(date(2026, 6, 2))

    assert result["sent"] is False
    assert len(sender.sent) == 0


def test_send_daily_digest_saves_digest_to_repository():
    settings = Settings(
        database_url="postgresql+psycopg://x:x@localhost/x",
        digest_recipients="",
    )
    repo = FakeRepository()
    pipeline = PipelineService(repository=repo, settings=settings)

    pipeline.send_daily_digest(date(2026, 6, 2))

    assert len(repo.saved_digests) == 1
    assert repo.saved_digests[0].digest_date == date(2026, 6, 2)


def test_send_pending_critical_alerts_sends_smtp_for_unsent_critical_items():
    critical = _critical_item()
    repo = FakeRepository(items_by_date={date(2026, 6, 2): [critical]})
    repo.stored_items[critical.item_id] = critical
    sender = FakeEmailSender()
    settings = Settings(
        database_url="postgresql+psycopg://x:x@localhost/x",
        alert_recipients="analyst@example.com",
    )
    pipeline = PipelineService(repository=repo, email_sender=sender, settings=settings)

    count = pipeline._send_pending_critical_alerts()

    assert count == 1
    assert len(sender.sent) == 1


def test_send_pending_critical_alerts_skips_already_alerted_items():
    critical = _critical_item()
    repo = FakeRepository(items_by_date={date(2026, 6, 2): [critical]})
    repo.stored_items[critical.item_id] = critical
    repo.alert_deliveries.add((critical.item_id, "immediate"))  # already sent
    sender = FakeEmailSender()
    settings = Settings(
        database_url="postgresql+psycopg://x:x@localhost/x",
        alert_recipients="analyst@example.com",
    )
    pipeline = PipelineService(repository=repo, email_sender=sender, settings=settings)

    count = pipeline._send_pending_critical_alerts()

    assert count == 0
    assert len(sender.sent) == 0
