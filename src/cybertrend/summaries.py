from __future__ import annotations

from typing import Mapping, Protocol

from cybertrend.models import CVEEnrichment, TrendItem
from cybertrend.text import collapse_whitespace


class SummaryProvider(Protocol):
    def summarize(self, item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> TrendItem: ...


class RuleSummaryProvider:
    def summarize(self, item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> TrendItem:
        cve_notes = []
        for cve in item.cves:
            enrichment = enrichments.get(cve)
            if enrichment and enrichment.vulnerability_name:
                cve_notes.append(f"{cve}: {enrichment.vulnerability_name}")
            else:
                cve_notes.append(cve)

        what_happened = item.summary or collapse_whitespace(item.title)
        if item.exploit_evidence:
            what_happened = f"{what_happened} Evidence: {item.exploit_evidence}."

        if item.what_went_wrong:
            what_went_wrong = item.what_went_wrong
        elif cve_notes:
            what_went_wrong = "The item references " + ", ".join(cve_notes) + "."
        else:
            what_went_wrong = "The source did not include enough structured vulnerability detail."

        if item.kev_flag:
            why_now = (
                "CISA KEV or exploit evidence indicates defenders should prioritize action now."
            )
        elif item.epss_percentile and item.epss_percentile >= 0.9:
            why_now = "EPSS indicates a high likelihood of exploitation activity."
        else:
            why_now = "The signal is worth tracking for trend and source-corroboration changes."

        return item.model_copy(
            update={
                "summary": collapse_whitespace(what_happened)[:800],
                "what_went_wrong": collapse_whitespace(what_went_wrong)[:800],
                "why_this_matters_now": collapse_whitespace(why_now)[:800],
            }
        )


class HybridSummaryProvider:
    """Rules-first summarizer with an optional injected LLM summarizer."""

    def __init__(self, llm_provider: SummaryProvider | None = None):
        self.rules = RuleSummaryProvider()
        self.llm_provider = llm_provider

    def summarize(self, item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> TrendItem:
        grounded = self.rules.summarize(item, enrichments)
        if not self.llm_provider or not item.cves:
            return grounded
        try:
            candidate = self.llm_provider.summarize(grounded, enrichments)
        except Exception:
            return grounded
        if not candidate.summary or not candidate.what_went_wrong:
            return grounded
        return candidate
