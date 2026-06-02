from datetime import datetime, timezone

import cybertrend.services.ingestion as ingestion_module
from cybertrend.models import CVEEnrichment, SourceType, TrendItem
from cybertrend.services.ingestion import IngestionService


class FakeRepository:
    def __init__(self, existing_items=None):
        self.items = []
        self.health = []
        self.enrichments = []
        self.existing_items = existing_items or {}

    def get_enrichment(self, cve):
        return None

    def get_item(self, item_id):
        return self.existing_items.get(item_id)

    def upsert_enrichment(self, enrichment):
        self.enrichments.append(enrichment)

    def upsert_item(self, item):
        self.items.append(item)

    def count_corroborating_sources(self, cves, current_source):
        return 0

    def upsert_source_health(self, source_name, source_type, *, success, error=None):
        self.health.append(
            {
                "source_name": source_name,
                "source_type": source_type,
                "success": success,
                "error": error,
            }
        )


class FakeNVDClient:
    def __init__(self):
        self.hours_back = None

    def fetch_recent(self, hours_back=24):
        self.hours_back = hours_back
        return [
            TrendItem(
                item_id="nvd:CVE-2026-99999",
                source_type=SourceType.NVD,
                source_name="nvd",
                title="CVE-2026-99999",
                url="https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
                published_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
                summary="A critical buffer overflow.",
                cves=["CVE-2026-99999"],
            )
        ]

    def fetch(self, cve):
        return CVEEnrichment(cve=cve, cvss_base=9.1)


class EmptyEnrichmentClient:
    def fetch(self, cve):
        return CVEEnrichment(cve=cve)


class FakeSummaryProvider:
    def __init__(self):
        self.calls = []

    def summarize(self, item, enrichments):
        self.calls.append(item.item_id)
        return item.model_copy(
            update={
                "summary": "Generated vulnerability summary",
                "what_went_wrong": "Generated attacker impact",
                "why_this_matters_now": "Generated organizational risk",
                "llm_analysis": {"headline": "Generated headline"},
            }
        )


def _trend_item(item_id="rss:test:1", *, raw=None, cves=None):
    return TrendItem(
        item_id=item_id,
        source_type=SourceType.RSS,
        source_name="thehackernews",
        title="Vendor product vulnerability",
        url="https://example.com/vuln",
        published_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        summary="Original source text",
        cves=cves or [],
        raw=raw or {"id": "entry-1"},
    )


def _nvd_item(item_id, *, cvss_base, published_at):
    return TrendItem(
        item_id=item_id,
        source_type=SourceType.NVD,
        source_name="nvd",
        title=item_id,
        url=f"https://nvd.nist.gov/vuln/detail/{item_id}",
        published_at=published_at,
        summary="NVD source text",
        cves=[item_id.replace("nvd:", "")],
        cvss_base=cvss_base,
        raw={"id": item_id},
    )


def test_ingestion_processes_nvd_jobs_through_fetch_recent():
    repository = FakeRepository()
    nvd_client = FakeNVDClient()
    ingestion = IngestionService(
        repository=repository,
        nvd_client=nvd_client,
        epss_client=EmptyEnrichmentClient(),
        kev_client=EmptyEnrichmentClient(),
        tenable_client=EmptyEnrichmentClient(),
    )

    stored = ingestion.process_job(
        {"source_type": "nvd", "source_name": "nvd", "hours_back": 48}
    )

    assert stored == 1
    assert nvd_client.hours_back == 48
    assert repository.items[0].item_id == "nvd:CVE-2026-99999"
    assert repository.health[-1] == {
        "source_name": "nvd",
        "source_type": "nvd",
        "success": True,
        "error": None,
    }


def test_process_items_reuses_existing_llm_analysis_for_unchanged_item():
    incoming = _trend_item()
    existing = incoming.model_copy(
        update={
            "summary": "Existing vulnerability summary",
            "what_went_wrong": "Existing attacker impact",
            "why_this_matters_now": "Existing organizational risk",
            "llm_analysis": {"headline": "Existing headline"},
        }
    )
    repository = FakeRepository(existing_items={incoming.item_id: existing})
    summarizer = FakeSummaryProvider()
    ingestion = IngestionService(repository=repository, summarizer=summarizer)

    stored = ingestion.process_items([incoming])

    assert stored == 1
    assert summarizer.calls == []
    assert ingestion.last_stats.skipped_summaries == 1
    saved = repository.items[0]
    assert saved.llm_analysis == {"headline": "Existing headline"}
    assert saved.summary == "Existing vulnerability summary"
    assert saved.what_went_wrong == "Existing attacker impact"
    assert saved.why_this_matters_now == "Existing organizational risk"


def test_process_items_summarizes_new_items():
    incoming = _trend_item()
    repository = FakeRepository()
    summarizer = FakeSummaryProvider()
    ingestion = IngestionService(repository=repository, summarizer=summarizer)

    stored = ingestion.process_items([incoming])

    assert stored == 1
    assert summarizer.calls == [incoming.item_id]
    assert ingestion.last_stats.skipped_summaries == 0
    assert repository.items[0].llm_analysis == {"headline": "Generated headline"}


def test_process_job_limits_rss_items_before_expensive_processing(monkeypatch):
    class FakeRSSConnector:
        def __init__(self, source_name, url):
            pass

        def fetch(self):
            return [
                _trend_item("rss:test:1"),
                _trend_item("rss:test:2"),
                _trend_item("rss:test:3"),
            ]

    monkeypatch.setattr(ingestion_module, "RSSConnector", FakeRSSConnector)
    repository = FakeRepository()
    summarizer = FakeSummaryProvider()
    ingestion = IngestionService(
        repository=repository,
        summarizer=summarizer,
        max_items_per_source=2,
    )

    stored = ingestion.process_job(
        {"source_type": "rss", "source_name": "test", "url": "https://example.com/feed"}
    )

    assert stored == 2
    assert summarizer.calls == ["rss:test:1", "rss:test:2"]
    assert ingestion.last_stats.fetched_items == 3
    assert ingestion.last_stats.processed_items == 2
    assert ingestion.last_stats.limited_items == 1


def test_process_job_limit_prefers_higher_signal_items_before_expensive_processing():
    class FakeNVDClient:
        def fetch_recent(self, hours_back=24):
            return [
                _nvd_item(
                    "nvd:CVE-2026-0001",
                    cvss_base=4.0,
                    published_at=datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc),
                ),
                _nvd_item(
                    "nvd:CVE-2026-0002",
                    cvss_base=9.8,
                    published_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
                ),
            ]

        def fetch(self, cve):
            return CVEEnrichment(cve=cve, cvss_base=9.8 if cve.endswith("0002") else 4.0)

    repository = FakeRepository()
    summarizer = FakeSummaryProvider()
    ingestion = IngestionService(
        repository=repository,
        nvd_client=FakeNVDClient(),
        epss_client=EmptyEnrichmentClient(),
        kev_client=EmptyEnrichmentClient(),
        tenable_client=EmptyEnrichmentClient(),
        summarizer=summarizer,
        max_nvd_items=1,
    )

    stored = ingestion.process_job({"source_type": "nvd", "source_name": "nvd"})

    assert stored == 1
    assert summarizer.calls == ["nvd:CVE-2026-0002"]
    assert ingestion.last_stats.limited_items == 1
