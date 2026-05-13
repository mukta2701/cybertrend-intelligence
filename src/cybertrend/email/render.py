from __future__ import annotations

from collections import Counter
from html import escape
from typing import Iterable, List

from cybertrend.models import DigestPayload, RenderedEmail, TrendItem


def _score(value: float) -> str:
    return str(int(round(value)))


def _source(item: TrendItem) -> str:
    return item.community or item.source_name


def _item_html(item: TrendItem) -> str:
    cves = ", ".join(escape(cve) for cve in item.cves) or "None identified"
    what_happened = escape(item.summary or "No summary available.")
    what_went_wrong = escape(item.what_went_wrong or "Not yet determined.")
    why_now = escape(
        item.why_this_matters_now
        or item.exploit_evidence
        or "Track for additional corroboration."
    )
    return f"""
    <article style="border:1px solid #d7dde5;border-radius:6px;padding:16px;margin:12px 0;">
      <h3 style="margin:0 0 8px;">{escape(item.title)}</h3>
      <p><strong>Source:</strong> {escape(_source(item))}</p>
      <p><strong>Criticality Score:</strong> {_score(item.criticality_score)}/100 &nbsp;
         <strong>Confidence Score:</strong> {_score(item.confidence_score)}/100 &nbsp;
         <strong>Severity:</strong> {escape(item.severity_label)}</p>
      <p><strong>What happened:</strong> {what_happened}</p>
      <p><strong>What went wrong:</strong> {what_went_wrong}</p>
      <p><strong>CVE(s):</strong> {cves}</p>
      <p><strong>Why this matters now:</strong> {why_now}</p>
      <p><a href="{escape(item.url)}">Link to thread/article/advisory</a></p>
    </article>
    """


def _item_text(item: TrendItem) -> str:
    cves = ", ".join(item.cves) or "None identified"
    why_now = (
        item.why_this_matters_now
        or item.exploit_evidence
        or "Track for additional corroboration."
    )
    return "\n".join(
        [
            f"Title: {item.title}",
            f"Source: {_source(item)}",
            f"Criticality Score: {_score(item.criticality_score)}/100",
            f"Confidence Score: {_score(item.confidence_score)}/100",
            f"Severity: {item.severity_label}",
            f"What happened: {item.summary or 'No summary available.'}",
            f"What went wrong: {item.what_went_wrong or 'Not yet determined.'}",
            f"CVE(s): {cves}",
            f"Why this matters now: {why_now}",
            f"Link to thread/article/advisory: {item.url}",
        ]
    )


def render_immediate_alert(item: TrendItem) -> RenderedEmail:
    subject = (
        f"[CRITICAL][Cyber Threat] {item.title[:90]} | "
        f"Score {_score(item.criticality_score)}/100 | Source {_source(item)}"
    )
    html = f"<html><body><h2>Critical Cyber Threat Alert</h2>{_item_html(item)}</body></html>"
    text = "Critical Cyber Threat Alert\n\n" + _item_text(item)
    return RenderedEmail(subject=subject, html=html, text=text)


def _all_items(payload: DigestPayload) -> Iterable[TrendItem]:
    for section in payload.sections:
        for item in section.items:
            yield item


def render_daily_digest(payload: DigestPayload) -> RenderedEmail:
    counts = Counter(item.severity_label for item in _all_items(payload))
    subject = (
        f"[Daily Cyber Threat Digest] {payload.digest_date.isoformat()} | "
        f"Critical: {counts['Critical']} High: {counts['High']} Medium: {counts['Medium']}"
    )

    html_sections: List[str] = []
    text_sections: List[str] = []
    for section in payload.sections:
        html_items = "".join(_item_html(item) for item in section.items)
        if not html_items:
            html_items = "<p>No items.</p>"
        html_sections.append(f"<section><h2>{escape(section.name)}</h2>{html_items}</section>")

        text_items = "\n\n".join(_item_text(item) for item in section.items) or "No items."
        text_sections.append(f"{section.name}\n{'=' * len(section.name)}\n{text_items}")

    footer_html = ""
    footer_text = ""
    if payload.source_quality_footer:
        footer_html = (
            "<footer><h2>Trending Communities and Signal Quality</h2>"
            f"<p>{escape(payload.source_quality_footer)}</p></footer>"
        )
        footer_text = (
            f"\n\nTrending Communities and Signal Quality\n{payload.source_quality_footer}"
        )

    html = "<html><body>" + "".join(html_sections) + footer_html + "</body></html>"
    text = "\n\n".join(text_sections) + footer_text
    return RenderedEmail(subject=subject, html=html, text=text)
