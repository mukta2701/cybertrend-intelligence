from __future__ import annotations

import json
import re
from typing import Mapping

from openai import OpenAI

from cybertrend.models import CVEEnrichment, TrendItem

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://\S+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _sanitize_for_prompt(value: str) -> str:
    sanitized = EMAIL_RE.sub("[email redacted]", value)
    sanitized = URL_RE.sub("[url redacted]", sanitized)
    sanitized = IPV4_RE.sub("[ip redacted]", sanitized)
    return sanitized[:1200]


class OpenAISummaryProvider:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def summarize(self, item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> TrendItem:
        cve_context = ", ".join(item.cves) or "no specific CVEs"
        title = _sanitize_for_prompt(item.title)
        current_summary = _sanitize_for_prompt(item.summary or "none")
        prompt = (
            "You are a cybersecurity analyst. Summarize this threat intelligence item.\n\n"
            f"Title: {title}\n"
            f"CVEs: {cve_context}\n"
            f"Current summary: {current_summary}\n"
            f"Severity: {item.severity_label}\n\n"
            "Return JSON with exactly these keys:\n"
            "- summary: 1-2 sentences on what happened (max 300 characters)\n"
            "- what_went_wrong: the vulnerability or issue (max 300 characters)\n"
            "- why_this_matters_now: why defenders should act now (max 300 characters)"
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=400,
        )
        data = json.loads(response.choices[0].message.content)
        summary = str(data.get("summary") or "").strip()
        what_went_wrong = str(data.get("what_went_wrong") or "").strip()
        why_now = str(data.get("why_this_matters_now") or "").strip()
        if not summary or not what_went_wrong:
            return item
        return item.model_copy(
            update={
                "summary": summary[:800],
                "what_went_wrong": what_went_wrong[:800],
                "why_this_matters_now": why_now[:800],
            }
        )
