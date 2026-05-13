from datetime import datetime, timezone

from cybertrend.dedupe import canonicalize_url, dedupe_key
from cybertrend.models import (
    CVEEnrichment,
    EngagementMetrics,
    SourceType,
    TrendItem,
)
from cybertrend.scoring import score_item
from cybertrend.text import extract_cves


def make_item(**overrides):
    base = {
        "item_id": "item-1",
        "source_type": SourceType.REDDIT,
        "source_name": "reddit",
        "community": "netsec",
        "title": "Exploit for CVE-2026-12345 observed in the wild",
        "url": "https://example.com/post?utm_source=reddit#comments",
        "published_at": datetime(2026, 5, 13, 7, 30, tzinfo=timezone.utc),
        "summary": "Security researchers report active exploitation.",
        "what_went_wrong": "",
        "cves": ["CVE-2026-12345"],
        "cvss_base": 9.8,
        "epss_probability": 0.84,
        "epss_percentile": 0.96,
        "kev_flag": True,
        "tenable_vpr": 9.4,
        "exploit_evidence": "active exploitation observed",
        "engagement_metrics": EngagementMetrics(score=120, comments=43, upvote_ratio=0.94),
    }
    base.update(overrides)
    return TrendItem(**base)


def test_extract_cves_normalizes_and_deduplicates_ids():
    text = "Patch CVE-2026-12345, cve-2026-12345, and CVE-2025-999999 today."

    assert extract_cves(text) == ["CVE-2026-12345", "CVE-2025-999999"]


def test_canonicalize_url_removes_tracking_case_and_fragments():
    url = "HTTPS://Example.COM:443/a/b/?utm_source=x&b=2&a=1#thread"

    assert canonicalize_url(url) == "https://example.com/a/b?a=1&b=2"


def test_score_item_marks_kev_high_epss_item_as_critical_with_explainable_breakdown():
    item = make_item()
    enrichments = {
        "CVE-2026-12345": CVEEnrichment(
            cve="CVE-2026-12345",
            cvss_base=9.8,
            epss_probability=0.84,
            epss_percentile=0.96,
            kev=True,
            tenable_vpr=9.4,
            exploit_maturity="functional",
        )
    }

    scored = score_item(item, enrichments=enrichments, source_trust=0.9, corroboration_count=2)

    assert scored.severity_label == "Critical"
    assert scored.criticality_score >= 85
    assert scored.confidence_score >= 80
    assert scored.score_breakdown.criticality_weights["kev"] == 0.20
    assert scored.score_breakdown.confidence_inputs["cross_source_corroboration"] == 1.0


def test_score_item_reduces_confidence_for_viral_reddit_post_without_cve_evidence():
    item = make_item(
        cves=[], cvss_base=None, epss_percentile=None, kev_flag=False, tenable_vpr=None
    )

    scored = score_item(item, enrichments={}, source_trust=0.65, corroboration_count=0)

    assert scored.confidence_score < 55
    assert scored.severity_label in {"Medium", "Low"}


def test_dedupe_key_prefers_shared_cve_over_tracking_url_variants():
    first = make_item(
        url="https://vendor.example/advisory?utm_campaign=x", title="Vendor fixes bug"
    )
    second = make_item(url="https://vendor.example/advisory", title="Different headline")

    assert dedupe_key(first) == dedupe_key(second)
