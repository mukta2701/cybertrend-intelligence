from datetime import date, datetime, timezone

from cybertrend.email.render import render_daily_digest, render_immediate_alert
from cybertrend.models import DigestPayload, DigestSection, EngagementMetrics, SourceType, TrendItem


def item(severity="Critical"):
    return TrendItem(
        item_id="critical-1",
        source_type=SourceType.REDDIT,
        source_name="reddit",
        community="netsec",
        title="Critical edge device exploit",
        url="https://example.com/advisory",
        published_at=datetime(2026, 5, 13, 7, 0, tzinfo=timezone.utc),
        summary="Attackers are exploiting exposed devices.",
        what_went_wrong="A remote command execution flaw allows unauthenticated requests.",
        cves=["CVE-2026-12345"],
        cvss_base=9.8,
        epss_probability=0.92,
        epss_percentile=0.98,
        kev_flag=True,
        tenable_vpr=9.6,
        exploit_evidence="CISA KEV and public exploit activity",
        engagement_metrics=EngagementMetrics(score=88, comments=19, upvote_ratio=0.91),
        criticality_score=96,
        confidence_score=91,
        severity_label=severity,
    )


def test_render_immediate_alert_contains_required_subject_and_plain_language_sections():
    message = render_immediate_alert(item())

    assert message.subject.startswith("[CRITICAL][Cyber Threat] Critical edge device exploit")
    assert "Score 96/100" in message.subject
    assert "What went wrong" in message.html
    assert "CVE-2026-12345" in message.text
    assert "https://example.com/advisory" in message.html


def test_render_daily_digest_groups_sections_and_counts_severity_labels():
    payload = DigestPayload(
        digest_date=date(2026, 5, 13),
        sections=[
            DigestSection(name="Critical - Act Now", severity="Critical", items=[item("Critical")]),
            DigestSection(
                name="High - Prioritize This Week", severity="High", items=[item("High")]
            ),
            DigestSection(name="Medium - Track", severity="Medium", items=[]),
        ],
        source_quality_footer="netsec: high signal",
    )

    message = render_daily_digest(payload)

    assert (
        message.subject == "[Daily Cyber Threat Digest] 2026-05-13 | Critical: 1 High: 1 Medium: 0"
    )
    assert "Critical - Act Now" in message.html
    assert "High - Prioritize This Week" in message.text
    assert "netsec: high signal" in message.html
