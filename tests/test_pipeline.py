from unittest.mock import MagicMock
from uuid import uuid4

import cybertrend.services.pipeline as pipeline_module
from cybertrend.config import Settings
from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.services.pipeline import PipelineService
from cybertrend.summaries import HybridSummaryProvider


class FakeIngestionService:
    def __init__(self):
        self.jobs = []

    def process_job(self, job):
        self.jobs.append(job)
        return 2


def test_manual_run_processes_all_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 7
    assert result["processed_jobs"] == 7
    assert result["stored_items"] == 14
    assert len(result["failed_jobs"]) == 0
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
        email_from="alerts@example.com",
        llm_provider="openai",
        llm_api_key="sk-test",
    )

    service = PipelineService.from_settings(settings)

    assert isinstance(service.email_sender, SMTPEmailSender)
    assert service.email_sender.user == "sender@gmail.com"
    assert service.email_sender.from_email == "alerts@example.com"
    assert isinstance(service.ingestion_service.summarizer, HybridSummaryProvider)
    assert isinstance(service.ingestion_service.summarizer.llm_provider, FakeOpenAISummaryProvider)
    assert service.ingestion_service.summarizer.llm_provider.api_key == "sk-test"
