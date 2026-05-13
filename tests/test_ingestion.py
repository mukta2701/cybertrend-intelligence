from datetime import datetime, timezone

from cybertrend.models import CVEEnrichment, SourceType, TrendItem
from cybertrend.services.ingestion import IngestionService


class FakeRepository:
    def __init__(self):
        self.items = []
        self.health = []
        self.enrichments = []

    def get_enrichment(self, cve):
        return None

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
