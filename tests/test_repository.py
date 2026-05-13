from datetime import date, datetime, timezone
from unittest.mock import MagicMock

from cybertrend.db.models import TrendItemRecord
from cybertrend.db.repository import Repository
from cybertrend.models import CVEEnrichment, DigestPayload


def _session():
    return MagicMock()


def test_upsert_enrichment_calls_execute_and_commit():
    session = _session()
    repo = Repository(session)
    enrichment = CVEEnrichment(cve="CVE-2026-12345", cvss_base=9.8, kev=True)

    repo.upsert_enrichment(enrichment)

    session.execute.assert_called_once()
    session.commit.assert_called_once()


def test_get_enrichment_returns_none_when_record_missing():
    session = _session()
    session.get.return_value = None
    repo = Repository(session)

    result = repo.get_enrichment("CVE-2026-12345")

    assert result is None


def test_upsert_source_health_creates_record_on_success():
    session = _session()
    session.get.return_value = None
    repo = Repository(session)

    repo.upsert_source_health("reddit_netsec", "rss", success=True)

    session.add.assert_called_once()
    session.commit.assert_called_once()
    record = session.add.call_args[0][0]
    assert record.source_name == "reddit_netsec"
    assert record.consecutive_failures == 0
    assert record.last_success_at is not None


def test_upsert_source_health_increments_failure_count_on_existing_record():
    session = _session()
    existing = MagicMock()
    existing.consecutive_failures = 2
    session.get.return_value = existing
    repo = Repository(session)

    repo.upsert_source_health("reddit_netsec", "rss", success=False, error="timeout")

    assert existing.consecutive_failures == 3
    assert existing.last_error == "timeout"
    session.commit.assert_called_once()


def test_build_digest_from_items_groups_by_severity():
    record = MagicMock(spec=TrendItemRecord)
    record.item_id = "item-1"
    record.source_type = "rss"
    record.source_name = "reddit_netsec"
    record.community = "netsec"
    record.title = "Critical bug"
    record.url = "https://example.com"
    record.published_at = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    record.summary = "summary"
    record.what_went_wrong = ""
    record.why_this_matters_now = ""
    record.cves = ["CVE-2026-12345"]
    record.cvss_base = 9.8
    record.epss_probability = None
    record.epss_percentile = None
    record.kev_flag = True
    record.tenable_vpr = None
    record.exploit_evidence = None
    record.engagement_metrics = {}
    record.criticality_score = 91.0
    record.confidence_score = 80.0
    record.severity_label = "Critical"
    record.score_breakdown = {}
    record.raw = {}

    session = _session()
    session.scalars.return_value = [record]
    repo = Repository(session)

    payload = repo.build_digest_from_items(date(2026, 5, 13))

    assert isinstance(payload, DigestPayload)
    critical_section = next(s for s in payload.sections if s.severity == "Critical")
    assert len(critical_section.items) == 1
    assert critical_section.items[0].item_id == "item-1"
