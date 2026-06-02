from datetime import date, datetime, timezone

from cybertrend.email.render import (
    _SOURCE_LABELS,
    _action_chips_html,
    _derive_action_type,
    _derive_timeframe,
    _item_compact_html,
    _item_compact_text,
    _item_html,
    _item_minimal_html,
    _item_minimal_text,
    _item_text,
    _source_label,
    _top_summary_bullets,
    render_daily_digest,
    render_immediate_alert,
)
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


def test_source_label_reddit_pwnhub():
    i = item()
    i = i.model_copy(update={"source_name": "reddit_pwnhub", "community": None})
    assert _source_label(i) == "r/pwnhub"


def test_footer_contains_all_source_labels():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[DigestSection(name="Critical Threats", severity="Critical", items=[item()])],
    )
    message = render_daily_digest(payload)
    for label in _SOURCE_LABELS.values():
        assert label in message.html, f"Footer missing: {label}"
    assert "r/pwnhub" in message.html


# ── Task 2: _derive_action_type, _derive_timeframe ───────────────────────────

def test_derive_action_type_patch():
    assert _derive_action_type("Patch to 9.18.4+; restrict management interface.") == "Patch"


def test_derive_action_type_update():
    assert _derive_action_type("Update the firmware to the latest version.") == "Patch"


def test_derive_action_type_monitor():
    assert _derive_action_type("Monitor for unusual outbound connections.") == "Monitor"


def test_derive_action_type_block():
    assert _derive_action_type("Restrict ingress from untrusted networks.") == "Block"


def test_derive_action_type_investigate():
    assert _derive_action_type("Investigate affected hosts for indicators of compromise.") == "Investigate"


def test_derive_action_type_fallback():
    assert _derive_action_type("Consult your vendor for further guidance.") == "Review exposure"


def test_derive_timeframe_kev_flag():
    i = item()  # kev_flag=True in fixture
    assert _derive_timeframe(i) == "Today"


def test_derive_timeframe_no_exploitation():
    i = TrendItem(
        item_id="med-1",
        source_type=SourceType.RSS,
        source_name="securityweek",
        title="Low risk advisory",
        url="https://example.com/low",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        exploit_evidence=None,
        epss_percentile=0.1,
        epss_probability=0.01,
        criticality_score=40,
        severity_label="Medium",
        llm_analysis={
            "headline": "Low risk advisory",
            "affected_assets": "Some product",
            "vulnerability": "Minor flaw",
            "threat": "Limited impact",
            "exploitation_status": "No exploitation reported",
            "organizational_risk": "Low",
            "recommended_action": "Monitor for vendor updates",
            "why_it_matters": "Low priority awareness item",
        },
    )
    assert _derive_timeframe(i) == "Monitor"


def test_derive_timeframe_poc():
    i = TrendItem(
        item_id="high-poc",
        source_type=SourceType.RSS,
        source_name="bleepingcomputer",
        title="PoC for GitLab runner SSRF",
        url="https://example.com/poc",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        exploit_evidence="proof-of-concept published on GitHub",
        epss_percentile=0.5,
        epss_probability=0.3,
        criticality_score=74,
        severity_label="High",
        llm_analysis={
            "headline": "GitLab Runner SSRF",
            "affected_assets": "GitLab CE/EE runners",
            "vulnerability": "SSRF via runner job metadata",
            "threat": "Internal network access",
            "exploitation_status": "PoC available",
            "organizational_risk": "Internal services reachable",
            "recommended_action": "Restrict runner network egress",
            "why_it_matters": "PoC lowers barrier to exploitation",
        },
    )
    assert _derive_timeframe(i) == "This week"


# ── Task 3: _top_summary_bullets ─────────────────────────────────────────────

def test_top_summary_bullets_uses_highest_scored_items():
    high_item = item("High")
    high_item = high_item.model_copy(update={"criticality_score": 50, "item_id": "low-score"})
    critical_item = item("Critical")  # criticality_score=96 from fixture

    bullets = _top_summary_bullets([high_item, critical_item])

    assert len(bullets) >= 1
    assert "Cisco ASA" in bullets[0]


def test_top_summary_bullets_falls_back_to_title_when_no_llm():
    i = TrendItem(
        item_id="no-llm",
        source_type=SourceType.RSS,
        source_name="nvd",
        title="CVE-2026-99999 affects Acme product",
        url="https://example.com/cve",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        criticality_score=60,
        severity_label="High",
        llm_analysis=None,
    )
    bullets = _top_summary_bullets([i])
    assert bullets[0] == "CVE-2026-99999 affects Acme product"


def test_top_summary_bullets_respects_n_limit():
    items = [
        item("Critical").model_copy(update={"item_id": f"item-{x}", "criticality_score": 90 - x})
        for x in range(10)
    ]
    bullets = _top_summary_bullets(items, n=3)
    assert len(bullets) == 3


# ── Task 4: _item_compact_html / _item_compact_text ──────────────────────────

def test_item_compact_html_contains_headline_and_action():
    i = item("High")
    html = _item_compact_html(i)

    assert "Cisco ASA" in html
    assert "Patch to 9.18.4" in html
    assert 'href="https://example.com/advisory"' in html


def test_item_compact_html_omits_org_risk_and_vulnerability():
    i = item("High")
    html = _item_compact_html(i)

    assert "Org Risk" not in html
    assert "Vulnerability" not in html
    assert "Unpatched edge firewalls" not in html


def test_item_compact_html_shows_score():
    i = item("High")
    html = _item_compact_html(i)
    assert "96/100" in html


def test_item_compact_text_contains_headline_action_link():
    i = item("High")
    text = _item_compact_text(i)

    assert "Cisco ASA" in text
    assert "Patch to 9.18.4" in text
    assert "https://example.com/advisory" in text


# ── Task 5: _item_minimal_html / _item_minimal_text ──────────────────────────

def test_item_minimal_html_is_one_linked_line():
    i = item("Medium")
    html = _item_minimal_html(i)

    assert "Cisco ASA" in html
    assert 'href="https://example.com/advisory"' in html
    assert "96" in html
    assert "border-radius:8px" not in html


def test_item_minimal_text_is_single_line():
    i = item("Medium")
    text = _item_minimal_text(i)

    assert "Cisco ASA" in text
    assert "\n" not in text


# ── Task 6: _item_html — action first, show_vulnerability param ───────────────

def test_item_html_action_appears_before_affected_field():
    i = item("Critical")
    html = _item_html(i, "Critical")

    action_pos = html.find("background:#ebf8ff")
    affected_pos = html.upper().find("AFFECTED")
    assert action_pos < affected_pos, "Action box must appear before the Affected field row"


def test_item_html_show_vulnerability_false_omits_vulnerability_row():
    i = item("Critical")
    html = _item_html(i, "Critical", show_vulnerability=False)
    assert "VULNERABILITY" not in html.upper()


def test_item_html_show_vulnerability_true_keeps_vulnerability_row():
    i = item("Critical")
    html = _item_html(i, "Critical", show_vulnerability=True)
    assert "VULNERABILITY" in html.upper()


def test_item_html_default_show_vulnerability_is_true():
    i = item("Critical")
    html = _item_html(i, "Critical")
    assert "VULNERABILITY" in html.upper()


# ── Task 7: render_daily_digest restructure ───────────────────────────────────

def test_render_daily_digest_contains_today_in_30_seconds_block():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "Today in 30 seconds" in message.html
    assert "Today in 30 seconds" in message.text
    assert "Cisco ASA" in message.html


def test_render_daily_digest_contains_top_actions_block():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "Top actions" in message.html
    assert "Today" in message.html


def test_render_daily_digest_critical_uses_full_card_without_vulnerability():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "AFFECTED" in message.html.upper()
    assert "THREAT" in message.html.upper()
    assert "ORG RISK" in message.html.upper()
    assert "VULNERABILITY" not in message.html.upper()


def test_render_daily_digest_high_uses_compact_card():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="High Priority", severity="High", items=[item("High")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "96/100" in message.html
    assert "ORG RISK" not in message.html.upper()


def test_render_daily_digest_medium_uses_minimal_list():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Medium Risk", severity="Medium", items=[item("Medium")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "Cisco ASA" in message.html
    assert "background:#ebf8ff" not in message.html


def test_render_daily_digest_empty_section_produces_no_html():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
            DigestSection(name="High Priority", severity="High", items=[]),
            DigestSection(name="Medium Risk", severity="Medium", items=[]),
        ],
    )
    message = render_daily_digest(payload)
    assert "No items today" not in message.html
    assert "High Priority" not in message.html
    assert "Medium Risk" not in message.html


# ── Task 8: action chips ──────────────────────────────────────────────────────

def test_action_chips_rendered_when_llm_action_fields_present():
    i = item().model_copy(update={"llm_analysis": {
        **item().llm_analysis,
        "action_type": "Patch",
        "action_owner": "Network team",
        "timeframe": "Now",
    }})

    html = _item_html(i, "Critical")

    assert "Patch" in html
    assert "Network team" in html
    assert "Now" in html


def test_action_chips_absent_when_llm_action_fields_missing():
    base = item()
    i = base.model_copy(update={"llm_analysis": {
        k: v for k, v in base.llm_analysis.items()
        if k not in ("action_type", "action_owner", "timeframe")
    }})

    chips = _action_chips_html(i, "Critical")

    assert chips == ""


def test_action_chips_now_timeframe_uses_critical_red():
    i = item().model_copy(update={"llm_analysis": {
        **item().llm_analysis,
        "action_type": "Patch",
        "action_owner": "SOC",
        "timeframe": "Now",
    }})

    chips = _action_chips_html(i, "Critical")

    assert "#c0392b" in chips


def test_action_chips_text_line_included_in_plain_text_output():
    i = item().model_copy(update={"llm_analysis": {
        **item().llm_analysis,
        "action_type": "Patch",
        "action_owner": "Network team",
        "timeframe": "Today",
    }})

    text = _item_text(i)

    assert "Patch" in text
    assert "Network team" in text
    assert "Today" in text
