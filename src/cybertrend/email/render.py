from __future__ import annotations

from collections import Counter
from html import escape
from typing import Iterable, List

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


def _derive_exploitation(item: TrendItem) -> str:
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


def _item_html(item: TrendItem, severity: str = "") -> str:
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
        + field_row("Vulnerability", vuln)
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

    return (
        f'<div style="background:#ffffff;border-radius:8px;margin:0 0 16px;'
        f'box-shadow:0 1px 3px rgba(0,0,0,0.08);overflow:hidden;'
        f'border:1px solid #e2e8f0;">'
        # coloured top stripe per severity
        f'<div style="height:3px;background:{sev_color["border"]};"></div>'
        f'<div style="padding:16px 18px;">'
        f'<div style="margin-bottom:8px;">{_exploit_badge(exploitation)}</div>'
        f'<h3 style="margin:0 0 6px;font-size:14px;line-height:1.4;font-weight:700;">'
        f'<a href="{escape(item.url)}" style="color:#1a202c;text-decoration:none;">'
        f'{escape(headline)}</a></h3>'
        f'<div style="margin-bottom:12px;">{meta_pills}</div>'
        f'<table style="border-collapse:collapse;width:100%;">{rows}</table>'
        f'{action_html}'
        f'{why_html}'
        f'{cves_html}'
        f'<p style="margin:10px 0 0;font-size:12px;">'
        f'<a href="{escape(item.url)}" style="color:#3182ce;text-decoration:none;'
        f'font-weight:600;">Read full article →</a></p>'
        f'</div></div>'
    )


def _item_text(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    lines = [
        _llm(item, "headline") or item.title,
        f"Source: {_source_label(item)} | Score: {_score(item.criticality_score)}/100",
        f"Exploitation: {exploitation}",
    ]
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
    counts = Counter(item.severity_label for item in _all_items(payload))
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
        sev_color = _SEV_COLORS.get(sev_key, _SEV_COLORS["Medium"])

        section_header = (
            f'<div style="background:{sev_color["bg"]};padding:10px 18px;margin:0 0 16px;">'
            f'<span style="font-size:13px;font-weight:800;color:#fff;'
            f'text-transform:uppercase;letter-spacing:1px;">{escape(sev_label)}</span>'
            f'<span style="font-size:12px;color:rgba(255,255,255,0.7);margin-left:8px;">'
            f'({len(items)})</span>'
            f'</div>'
        )

        if items:
            cards = "".join(_item_html(item, sev_key) for item in items)
            content = f'<div style="padding:0 16px 8px;">{cards}</div>'
        else:
            content = (
                '<p style="padding:0 18px 16px;font-size:13px;color:#a0aec0;">'
                'No items today.</p>'
            )

        html_sections.append(
            f'<div style="margin-bottom:24px;">{section_header}{content}</div>'
        )

        text_items = "\n\n".join(_item_text(i) for i in items) or "No items today."
        text_sections.append(f"{sev_label} ({len(items)})\n{'─'*40}\n{text_items}")

    # ── Footer ───────────────────────────────────────────────────────────────
    quality_html = ""
    quality_text = ""
    if payload.source_quality_footer:
        quality_html = (
            f'<p style="font-size:12px;color:#718096;margin:0 0 8px;">'
            f'<strong>Source quality:</strong> {escape(payload.source_quality_footer)}</p>'
        )
        quality_text = f"\nSource quality: {payload.source_quality_footer}"

    footer = (
        '<div style="background:#0f1923;padding:16px 24px;border-radius:0 0 8px 8px;">'
        + quality_html
        + '<p style="margin:0;font-size:11px;color:#4a5568;">'
        'Cybertrend Intelligence &nbsp;·&nbsp; Automated daily briefing &nbsp;·&nbsp; '
        'Sources: NVD · Tenable · BleepingComputer · The Hacker News · Krebs · SANS ISC · '
        'Dark Reading · SecurityWeek'
        '</p></div>'
    )

    html = (
        '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        '<body style="font-family:-apple-system,Arial,sans-serif;background:#edf2f7;'
        'padding:20px 10px;margin:0;">'
        '<div style="max-width:640px;margin:0 auto;border-radius:8px;overflow:hidden;'
        'box-shadow:0 4px 12px rgba(0,0,0,0.12);">'
        + header
        + '<div style="background:#f7fafc;">'
        + "".join(html_sections)
        + '</div>'
        + footer
        + '</div></body></html>'
    )
    text = f"CYBER THREAT DIGEST — {date_str}\n\n" + "\n\n".join(text_sections) + quality_text
    return RenderedEmail(subject=subject, html=html, text=text)
