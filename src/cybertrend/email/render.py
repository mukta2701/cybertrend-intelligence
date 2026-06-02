from __future__ import annotations

from collections import Counter
from html import escape
from typing import Iterable, List, Optional

from cybertrend.models import DigestPayload, RenderedEmail, TrendItem

_SOURCE_LABELS = {
    "bleepingcomputer": "BleepingComputer",
    "thehackernews": "The Hacker News",
    "krebsonsecurity": "Krebs on Security",
    "sans_isc": "SANS ISC",
    "darkreading": "Dark Reading",
    "securityweek": "SecurityWeek",
    "tenable": "Tenable Research",
    "nvd": "NVD / NIST",
    "reddit_pwnhub": "r/pwnhub",
}

_SEV_COLORS = {
    "Critical": {"bg": "#c0392b", "light": "#fff5f5", "border": "#e53e3e"},
    "High":     {"bg": "#c05621", "light": "#fffaf0", "border": "#dd6b20"},
    "Medium":   {"bg": "#975a16", "light": "#fffff0", "border": "#d69e2e"},
}

_EXPLOIT_COLORS = {
    "actively exploited": "#c0392b",
    "poc available":      "#c05621",
    "exploitation likely":"#c05621",
    "no exploitation":    "#276749",
    "unknown":            "#4a5568",
}


def _score(v: float) -> str:
    return str(int(round(v)))


def _source_label(item: TrendItem) -> str:
    key = (item.community or item.source_name or "").lower()
    return _SOURCE_LABELS.get(key, (item.community or item.source_name or "Unknown").title())


def _truncate(text: str, limit: int = 280) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def _derive_exploitation(item: TrendItem) -> Optional[str]:
    if item.kev_flag:
        return "Actively Exploited — CISA KEV"
    evidence = (item.exploit_evidence or "").lower()
    if any(w in evidence for w in ("wild", "active", "ransomware", "apt")):
        return "Actively Exploited"
    if any(w in evidence for w in ("poc", "proof-of-concept", "public exploit")):
        return "PoC Available"
    if item.epss_percentile and item.epss_percentile >= 0.9:
        return f"Exploitation Likely (EPSS {item.epss_probability:.0%})"
    return None


def _llm(item: TrendItem, key: str, fallback: str = "") -> str:
    if item.llm_analysis:
        v = item.llm_analysis.get(key) or ""
        if v and v.strip().lower() not in ("not stated", "unknown", ""):
            return v.strip()
    return fallback


def _exploit_badge(status: str) -> str:
    color = "#4a5568"
    status_l = status.lower()
    for k, c in _EXPLOIT_COLORS.items():
        if k in status_l:
            color = c
            break
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:20px;'
        f'background:{color};color:#fff;font-size:11px;font-weight:700;'
        f'letter-spacing:0.4px;text-transform:uppercase;">'
        f'{escape(status)}</span>'
    )


def _meta_pill(text: str, bg: str = "#edf2f7", color: str = "#4a5568") -> str:
    return (
        f'<span style="display:inline-block;padding:2px 7px;border-radius:4px;'
        f'background:{bg};color:{color};font-size:11px;margin-right:4px;">'
        f'{escape(text)}</span>'
    )


def _action_badge(text: str, bg: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 7px;border-radius:3px;'
        f'background:{bg};color:#fff;font-size:10px;font-weight:700;margin-right:4px;">'
        f'{escape(text)}</span>'
    )


def _action_chips_html(item: TrendItem, severity: str = "") -> str:
    if not item.llm_analysis:
        return ""
    action_type  = item.llm_analysis.get("action_type")
    action_owner = item.llm_analysis.get("action_owner")
    timeframe    = item.llm_analysis.get("timeframe")
    if not any([action_type, action_owner, timeframe]):
        return ""
    sev = severity or item.severity_label
    type_bg = _SEV_COLORS.get(sev, _SEV_COLORS["Medium"])["bg"]
    _TF_COLORS = {"Now": "#c0392b", "Today": "#c05621", "This week": "#975a16"}
    tf_bg = _TF_COLORS.get(timeframe or "", "#718096")
    chips = ""
    if action_type:
        chips += _action_badge(action_type, type_bg)
    if action_owner:
        chips += _action_badge(action_owner, "#4a5568")
    if timeframe:
        chips += _action_badge(timeframe, tf_bg)
    return f'<div style="margin:4px 0 8px;">{chips}</div>'


def _action_chips_text(item: TrendItem) -> str:
    if not item.llm_analysis:
        return ""
    parts = [
        item.llm_analysis.get("action_type"),
        item.llm_analysis.get("action_owner"),
        item.llm_analysis.get("timeframe"),
    ]
    filled = [p for p in parts if p]
    return " | ".join(filled)


def _derive_action_type(action_text: str) -> str:
    text = action_text.lower()
    if any(w in text for w in ("patch", "update", "upgrade")):
        return "Patch"
    if any(w in text for w in ("monitor", "watch")):
        return "Monitor"
    if "investigate" in text:
        return "Investigate"
    if any(w in text for w in ("block", "restrict", "disable")):
        return "Block"
    return "Review exposure"


def _derive_timeframe(item: TrendItem) -> str:
    exploitation = (_derive_exploitation(item) or _llm(item, "exploitation_status", "")).lower()
    if item.kev_flag or "actively exploited" in exploitation:
        return "Today"
    if "poc" in exploitation or "exploitation likely" in exploitation:
        return "This week"
    return "Monitor"


def _top_summary_bullets(items: Iterable[TrendItem], n: int = 5) -> List[str]:
    sorted_items = sorted(items, key=lambda i: i.criticality_score, reverse=True)[:n]
    bullets = []
    for i in sorted_items:
        raw_action = _llm(i, "recommended_action", "")
        assets = _llm(i, "affected_assets") or i.title
        exploitation = _derive_exploitation(i) or _llm(i, "exploitation_status", "")
        prefix = f"{_derive_action_type(raw_action)} " if raw_action else ""
        if exploitation:
            bullets.append(f"{prefix}{assets} — {exploitation}")
        else:
            bullets.append(f"{prefix}{assets}")
    return bullets


def _item_html(item: TrendItem, severity: str = "", show_vulnerability: bool = True) -> str:
    sev_color = _SEV_COLORS.get(severity or item.severity_label, _SEV_COLORS["Medium"])
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    affected  = _llm(item, "affected_assets")
    vuln      = _llm(item, "vulnerability", item.summary or item.title)
    threat    = _llm(item, "threat", item.what_went_wrong)
    org_risk  = _llm(item, "organizational_risk", item.why_this_matters_now)
    action    = _llm(item, "recommended_action")
    why       = _llm(item, "why_it_matters")
    cves      = ", ".join(item.cves) if item.cves else ""

    meta_pills = _meta_pill(_source_label(item))
    meta_pills += _meta_pill(f"Score {_score(item.criticality_score)}/100")
    if item.cvss_base:
        meta_pills += _meta_pill(f"CVSS {item.cvss_base}")
    if item.epss_probability and item.epss_probability > 0.1:
        meta_pills += _meta_pill(f"EPSS {item.epss_probability:.0%}")

    def field_row(label: str, value: str, value_color: str = "#2d3748") -> str:
        if not value:
            return ""
        return (
            f'<tr>'
            f'<td style="padding:5px 12px 5px 0;font-size:11px;font-weight:700;'
            f'color:#718096;white-space:nowrap;vertical-align:top;'
            f'text-transform:uppercase;letter-spacing:0.5px;">{escape(label)}</td>'
            f'<td style="padding:5px 0;font-size:13px;color:{value_color};line-height:1.5;">'
            f'{escape(_truncate(value))}</td>'
            f'</tr>'
        )

    rows = (
        field_row("Affected", affected)
        + (field_row("Vulnerability", vuln) if show_vulnerability else "")
        + field_row("Threat", threat)
        + field_row("Org Risk", org_risk)
    )

    action_html = ""
    if action:
        action_html = (
            f'<div style="margin:12px 0 8px;padding:10px 14px;background:#ebf8ff;'
            f'border-left:3px solid #3182ce;border-radius:0 6px 6px 0;">'
            f'<span style="font-size:11px;font-weight:700;color:#2b6cb0;'
            f'text-transform:uppercase;letter-spacing:0.5px;">Action &nbsp;</span>'
            f'<span style="font-size:13px;color:#2c5282;">{escape(_truncate(action))}</span>'
            f'</div>'
        )

    why_html = ""
    if why:
        why_html = (
            f'<p style="margin:8px 0 0;font-size:12px;color:#718096;font-style:italic;">'
            f'{escape(_truncate(why))}</p>'
        )

    cves_html = ""
    if cves:
        cves_html = (
            f'<p style="margin:6px 0 0;font-size:11px;color:#a0aec0;">'
            f'CVEs: {escape(cves)}</p>'
        )

    chips = _action_chips_html(item, severity)

    return (
        f'<div style="background:#ffffff;border-radius:8px;margin:0 0 16px;'
        f'box-shadow:0 1px 3px rgba(0,0,0,0.08);overflow:hidden;'
        f'border:1px solid #e2e8f0;">'
        f'<div style="height:3px;background:{sev_color["border"]};"></div>'
        f'<div style="padding:16px 18px;">'
        f'<div style="margin-bottom:8px;">{_exploit_badge(exploitation)}</div>'
        f'{chips}'
        f'<h3 style="margin:0 0 6px;font-size:14px;line-height:1.4;font-weight:700;">'
        f'<a href="{escape(item.url)}" style="color:#1a202c;text-decoration:none;">'
        f'{escape(headline)}</a></h3>'
        f'<div style="margin-bottom:12px;">{meta_pills}</div>'
        f'{action_html}'
        f'<table style="border-collapse:collapse;width:100%;">{rows}</table>'
        f'{why_html}'
        f'{cves_html}'
        f'<p style="margin:10px 0 0;font-size:12px;">'
        f'<a href="{escape(item.url)}" style="color:#3182ce;text-decoration:none;'
        f'font-weight:600;">Read full article →</a></p>'
        f'</div></div>'
    )


def _item_text(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    chips_text = _action_chips_text(item)
    lines = [
        _llm(item, "headline") or item.title,
        f"Source: {_source_label(item)} | Score: {_score(item.criticality_score)}/100",
        f"Exploitation: {exploitation}",
    ]
    if chips_text:
        lines.append(f"Action scope: {chips_text}")
    for label, key, fallback in [
        ("Affected",     "affected_assets",    ""),
        ("Vulnerability","vulnerability",       item.summary),
        ("Threat",       "threat",              item.what_went_wrong),
        ("Org Risk",     "organizational_risk", item.why_this_matters_now),
        ("Action",       "recommended_action",  ""),
        ("Why Now",      "why_it_matters",      ""),
    ]:
        val = _llm(item, key, fallback).strip()
        if val:
            lines.append(f"{label}: {_truncate(val)}")
    if item.cves:
        lines.append(f"CVEs: {', '.join(item.cves)}")
    lines.append(f"Link: {item.url}")
    return "\n".join(lines)


def _item_compact_html(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    action = _llm(item, "recommended_action")
    source = _source_label(item)

    return (
        f'<div style="background:#ffffff;border-radius:6px;margin:0 0 8px;'
        f'border:1px solid #e2e8f0;border-left:4px solid #dd6b20;">'
        f'<div style="padding:10px 12px;">'
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;'
        f'gap:6px;margin-bottom:4px;">'
        f'<a href="{escape(item.url)}" style="font-size:13px;font-weight:700;color:#1a202c;'
        f'text-decoration:none;line-height:1.3;flex:1;">{escape(headline)}</a>'
        f'{_exploit_badge(exploitation)}'
        f'</div>'
        + (
            f'<p style="margin:0 0 4px;font-size:12px;color:#4a5568;line-height:1.4;">'
            f'{escape(_truncate(action))}</p>'
            if action else ''
        )
        + f'<p style="margin:0;font-size:11px;color:#a0aec0;">'
        f'Score {_score(item.criticality_score)}/100 &nbsp;·&nbsp; {escape(source)} &nbsp;·&nbsp; '
        f'<a href="{escape(item.url)}" style="color:#3182ce;font-weight:600;">Read →</a></p>'
        f'</div></div>'
    )


def _item_compact_text(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    action = _llm(item, "recommended_action", "")
    lines = [
        headline,
        f"[{exploitation}] Score: {_score(item.criticality_score)}/100 | {_source_label(item)}",
    ]
    if action:
        lines.append(f"Action: {_truncate(action)}")
    lines.append(f"Link: {item.url}")
    return "\n".join(lines)


def _item_minimal_html(item: TrendItem) -> str:
    headline = _llm(item, "headline") or item.title
    return (
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;'
        f'gap:8px;padding:5px 0;border-bottom:1px solid #f0f4f8;">'
        f'<div style="display:flex;align-items:flex-start;gap:7px;flex:1;">'
        f'<span style="width:6px;height:6px;background:#d69e2e;border-radius:50%;'
        f'flex-shrink:0;margin-top:5px;display:inline-block;"></span>'
        f'<a href="{escape(item.url)}" style="font-size:12px;color:#2d3748;'
        f'text-decoration:none;line-height:1.4;">{escape(headline)}</a>'
        f'</div>'
        f'<span style="font-size:11px;color:#a0aec0;white-space:nowrap;flex-shrink:0;">'
        f'{_score(item.criticality_score)}</span>'
        f'</div>'
    )


def _item_minimal_text(item: TrendItem) -> str:
    headline = _llm(item, "headline") or item.title
    return f"  • {_truncate(headline, 100)} [{_score(item.criticality_score)}]"


def _count_badge(label: str, count: int, bg: str) -> str:
    if count == 0:
        return ""
    return (
        f'<span style="display:inline-block;padding:4px 14px;border-radius:20px;'
        f'background:{bg};color:#fff;font-size:13px;font-weight:700;margin-right:8px;">'
        f'{count} {escape(label)}</span>'
    )


def render_immediate_alert(item: TrendItem) -> RenderedEmail:
    subject = f"[CRITICAL ALERT] {item.title[:80]} — Score {_score(item.criticality_score)}/100"
    html = (
        '<html><body style="font-family:-apple-system,Arial,sans-serif;'
        'background:#f7fafc;padding:20px;max-width:640px;margin:auto;">'
        '<div style="background:#c0392b;color:#fff;padding:16px 20px;border-radius:8px 8px 0 0;">'
        '<h2 style="margin:0;font-size:18px;">&#x1F6A8; Critical Threat Alert</h2>'
        '</div>'
        + _item_html(item, "Critical")
        + '</body></html>'
    )
    text = "CRITICAL THREAT ALERT\n\n" + _item_text(item)
    return RenderedEmail(subject=subject, html=html, text=text)


def _all_items(payload: DigestPayload) -> Iterable[TrendItem]:
    for section in payload.sections:
        for item in section.items:
            yield item


def render_daily_digest(payload: DigestPayload) -> RenderedEmail:
    all_items = list(_all_items(payload))
    counts = Counter(i.severity_label for i in all_items)
    date_str = payload.digest_date.strftime("%B %d, %Y")
    day_str  = payload.digest_date.strftime("%A")
    subject = (
        f"Cyber Threat Digest — {date_str} | "
        f"{counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium"
    )

    # ── Header ──────────────────────────────────────────────────────────────
    header = (
        '<div style="background:#0f1923;padding:28px 24px 20px;border-radius:8px 8px 0 0;">'
        '<p style="margin:0 0 4px;font-size:11px;color:#718096;'
        'text-transform:uppercase;letter-spacing:1px;">Automated Intelligence Brief</p>'
        '<h1 style="margin:0 0 6px;font-size:22px;color:#ffffff;font-weight:800;">'
        '&#x1F6E1; Cyber Threat Digest</h1>'
        f'<p style="margin:0 0 16px;font-size:13px;color:#a0aec0;">{day_str}, {date_str}</p>'
        '<div>'
        + _count_badge("Critical", counts["Critical"], "#c0392b")
        + _count_badge("High", counts["High"], "#c05621")
        + _count_badge("Medium", counts["Medium"], "#975a16")
        + '</div></div>'
    )

    # ── Today in 30 seconds ─────────────────────────────────────────────────
    bullets = _top_summary_bullets(all_items)
    if bullets:
        bullet_html = "".join(
            f'<p style="margin:0 0 5px;font-size:13px;color:#e2e8f0;padding-left:14px;'
            f'position:relative;line-height:1.5;">'
            f'<span style="position:absolute;left:0;color:#63b3ed;font-weight:800;">·</span>'
            f'{escape(b)}</p>'
            for b in bullets
        )
        summary_html = (
            '<div style="margin:0;padding:12px 16px;background:#1a2744;'
            'border-left:3px solid #63b3ed;">'
            '<p style="margin:0 0 8px;font-size:10px;font-weight:800;color:#63b3ed;'
            'text-transform:uppercase;letter-spacing:1px;">Today in 30 seconds</p>'
            + bullet_html
            + '</div>'
        )
        summary_text = "Today in 30 seconds\n" + "\n".join(f"- {b}" for b in bullets)
    else:
        summary_html = ""
        summary_text = ""

    # ── Top actions ─────────────────────────────────────────────────────────
    top_items = sorted(all_items, key=lambda i: i.criticality_score, reverse=True)[:5]
    if top_items:
        rows_html = ""
        rows_text = []
        for idx, i in enumerate(top_items, 1):
            action_type = (
                _llm(i, "action_type")
                or _derive_action_type(_llm(i, "recommended_action", ""))
            )
            action_owner = _llm(i, "action_owner")
            timeframe    = _llm(i, "timeframe") or _derive_timeframe(i)
            assets      = _llm(i, "affected_assets") or i.title
            tf_color    = "#c0392b" if timeframe in ("Now", "Today") else (
                "#975a16" if timeframe == "This week" else "#718096"
            )
            rows_html += (
                f'<tr>'
                f'<td style="padding:3px 8px 3px 0;font-size:12px;color:#718096;">{idx}.</td>'
                f'<td style="padding:3px 0;">'
                f'{_action_badge(action_type, "#553c9a")}'
                + (f'{_action_badge(action_owner, "#4a5568")}' if action_owner else "")
                + f'{_action_badge(timeframe, tf_color)}'
                f'<span style="font-size:12px;color:#2d3748;">'
                f'{escape(_truncate(assets, 80))}</span>'
                f'</td></tr>'
            )
            owner_str = f"[{action_owner}] " if action_owner else ""
            rows_text.append(
                f"{idx}. [{action_type}] {owner_str}[{timeframe}] {_truncate(assets, 80)}"
            )

        top_actions_html = (
            '<div style="margin:0;padding:12px 16px;background:#f7fafc;'
            'border-top:1px solid #e2e8f0;">'
            '<p style="margin:0 0 8px;font-size:10px;font-weight:800;color:#718096;'
            'text-transform:uppercase;letter-spacing:1px;">Top actions</p>'
            f'<table style="border-collapse:collapse;width:100%;">{rows_html}</table>'
            '</div>'
        )
        top_actions_text = "Top actions\n" + "\n".join(rows_text)
    else:
        top_actions_html = ""
        top_actions_text = ""

    # ── Sections ─────────────────────────────────────────────────────────────
    sev_order = [
        ("Critical", "Critical Threats"),
        ("High",     "High Priority"),
        ("Medium",   "Medium Risk"),
    ]
    html_sections: List[str] = []
    text_sections: List[str] = []

    section_map = {s.severity: s for s in payload.sections}

    for sev_key, sev_label in sev_order:
        section = section_map.get(sev_key)
        items = section.items if section else []
        if not items:
            continue
        sev_color = _SEV_COLORS.get(sev_key, _SEV_COLORS["Medium"])

        section_header = (
            f'<div style="background:{sev_color["bg"]};padding:10px 18px;margin:0 0 16px;">'
            f'<span style="font-size:13px;font-weight:800;color:#fff;'
            f'text-transform:uppercase;letter-spacing:1px;">{escape(sev_label)}</span>'
            f'<span style="font-size:12px;color:rgba(255,255,255,0.7);margin-left:8px;">'
            f'({len(items)})</span>'
            f'</div>'
        )

        if sev_key == "Critical":
            cards = "".join(_item_html(i, sev_key, show_vulnerability=False) for i in items)
            content = f'<div style="padding:0 16px 8px;">{cards}</div>'
            text_items = "\n\n".join(_item_text(i) for i in items)
        elif sev_key == "High":
            cards = "".join(_item_compact_html(i) for i in items)
            content = f'<div style="padding:0 16px 8px;">{cards}</div>'
            text_items = "\n\n".join(_item_compact_text(i) for i in items)
        else:
            list_items = "".join(_item_minimal_html(i) for i in items)
            content = (
                f'<div style="padding:0 16px 8px;">'
                f'<div style="background:#ffffff;border-radius:6px;padding:6px 12px;'
                f'border:1px solid #e2e8f0;">{list_items}</div>'
                f'</div>'
            )
            text_items = "\n".join(_item_minimal_text(i) for i in items)

        html_sections.append(
            f'<div style="margin-bottom:24px;">{section_header}{content}</div>'
        )
        text_sections.append(f"{sev_label} ({len(items)})\n{'─'*40}\n{text_items}")

    # ── Footer ───────────────────────────────────────────────────────────────
    quality_html = ""
    quality_text = ""
    if payload.source_quality_footer:
        quality_html = (
            f'<p style="font-size:12px;color:#718096;margin:0 0 8px;">'
            f'<strong>Source quality:</strong> {escape(payload.source_quality_footer)}</p>'
        )
        quality_text = payload.source_quality_footer

    footer = (
        '<div style="background:#0f1923;padding:16px 24px;border-radius:0 0 8px 8px;">'
        + quality_html
        + '<p style="margin:0;font-size:11px;color:#4a5568;">'
        f'Cybertrend Intelligence &nbsp;·&nbsp; Automated daily briefing &nbsp;·&nbsp; '
        f'Sources: {escape(" · ".join(_SOURCE_LABELS.values()))}'
        '</p></div>'
    )

    html = (
        '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        '<body style="font-family:-apple-system,Arial,sans-serif;background:#edf2f7;'
        'padding:20px 10px;margin:0;">'
        '<div style="max-width:640px;margin:0 auto;border-radius:8px;overflow:hidden;'
        'box-shadow:0 4px 12px rgba(0,0,0,0.12);">'
        + header
        + summary_html
        + top_actions_html
        + '<div style="background:#f7fafc;">'
        + "".join(html_sections)
        + '</div>'
        + footer
        + '</div></body></html>'
    )

    text_parts = [f"CYBER THREAT DIGEST — {date_str}"]
    if summary_text:
        text_parts.append(summary_text)
    if top_actions_text:
        text_parts.append(top_actions_text)
    text_parts.extend(text_sections)
    if quality_text:
        text_parts.append(f"Source quality: {quality_text}")
    text = "\n\n".join(text_parts)

    return RenderedEmail(subject=subject, html=html, text=text)
