from datetime import datetime, timezone
from unittest.mock import MagicMock

from cybertrend.db.repository import Repository
from cybertrend.models import CVEEnrichment


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
