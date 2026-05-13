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
