from datetime import date, datetime, timezone

from cybertrend.email.render import render_daily_digest, render_immediate_alert
from cybertrend.models import DigestPayload, DigestSection, EngagementMetrics, SourceType, TrendItem


def item(severity="Critical"):
    return TrendItem(
        item_id="critical-1",
        source_type=SourceType.RSS,
        source_name="thehackernews",
        title="Cisco ASA Auth Bypass Exploited in the Wild",
        url="https://example.com/advisory",
        published_at=datetime(2026, 5, 13, 7, 0, tzinfo=timezone.utc),
        summary="Authentication bypass in Cisco ASA VPN component.",
        what_went_wrong="Unauthenticated attacker can reach protected management functions.",
        why_this_matters_now="Internet-exposed firewalls risk full network compromise.",
        cves=["CVE-2026-12345"],
        cvss_base=9.8,
        epss_probability=0.92,
        epss_percentile=0.98,
        kev_flag=True,
        tenable_vpr=9.6,
        exploit_evidence="CISA KEV and active ransomware exploitation",
        engagement_metrics=EngagementMetrics(score=88, comments=19, upvote_ratio=0.91),
        criticality_score=96,
        confidence_score=91,
        severity_label=severity,
        llm_analysis={
            "headline": "Cisco ASA — Auth bypass enables unauthenticated remote access",
            "affected_assets": "Cisco ASA and FTD < 9.18.4",
            "vulnerability": "CVE-2026-12345 is an auth bypass in the Cisco ASA VPN component.",
            "threat": "An unauthenticated attacker can reach protected admin functions and take over the device.",
            "exploitation_status": "Actively exploited — CISA KEV and ransomware campaigns.",
            "organizational_risk": "Unpatched edge firewalls enable ransomware lateral movement.",
            "recommended_action": "Patch to 9.18.4+; restrict management interface to trusted IPs.",
            "why_it_matters": "Edge firewall compromise gives attackers full network visibility.",
        },
    )


def test_render_immediate_alert_contains_required_subject_and_plain_language_sections():
    message = render_immediate_alert(item())

    assert message.subject.startswith("[CRITICAL ALERT] Cisco ASA")
    assert "Score 96/100" in message.subject
    assert "Vulnerability" in message.html
    assert "Threat" in message.html
    assert "CVE-2026-12345" in message.text
    assert "https://example.com/advisory" in message.html


def test_render_daily_digest_groups_sections_and_counts_severity_labels():
    payload = DigestPayload(
        digest_date=date(2026, 5, 13),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
            DigestSection(name="High Priority", severity="High", items=[item("High")]),
            DigestSection(name="Medium Risk", severity="Medium", items=[]),
        ],
        source_quality_footer="netsec: high signal",
    )

    message = render_daily_digest(payload)

    assert message.subject == "Cyber Threat Digest — May 13, 2026 | 1 Critical, 1 High, 0 Medium"
    assert "Critical Threats" in message.html
    assert "High Priority" in message.text
    assert "netsec: high signal" in message.html
    assert "Actively Exploited" in message.html
    assert "Cisco ASA" in message.html
