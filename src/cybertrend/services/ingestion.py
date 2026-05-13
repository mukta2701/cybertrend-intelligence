from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from cybertrend.connectors.epss import EPSSClient
from cybertrend.connectors.kev import KEVClient
from cybertrend.connectors.nvd import NVDClient
from cybertrend.connectors.reddit import RedditClient
from cybertrend.connectors.rss import RSSConnector
from cybertrend.connectors.tenable import TenableVPRClient
from cybertrend.models import CVEEnrichment, TrendItem
from cybertrend.scoring import score_item
from cybertrend.services.enrichment import merge_enrichments
from cybertrend.summaries import HybridSummaryProvider


class IngestionService:
    def __init__(
        self,
        repository,
        alert_queue=None,
        reddit_client: Optional[RedditClient] = None,
        nvd_client: Optional[NVDClient] = None,
        epss_client: Optional[EPSSClient] = None,
        kev_client: Optional[KEVClient] = None,
        tenable_client: Optional[TenableVPRClient] = None,
        summarizer: Optional[HybridSummaryProvider] = None,
    ):
        self.repository = repository
        self.alert_queue = alert_queue
        self.reddit_client = reddit_client
        self.nvd_client = nvd_client or NVDClient()
        self.epss_client = epss_client or EPSSClient()
        self.kev_client = kev_client or KEVClient()
        self.tenable_client = tenable_client or TenableVPRClient()
        self.summarizer = summarizer or HybridSummaryProvider()

    def process_job(self, job: dict) -> int:
        source_type = job.get("source_type")
        items: List[TrendItem] = []
        if source_type == "reddit":
            if not self.reddit_client:
                raise RuntimeError("Reddit client is not configured")
            items = self.reddit_client.fetch_subreddit(job["community"])
        elif source_type == "rss":
            items = RSSConnector(source_name=job["source_name"], url=job["url"]).fetch()
        else:
            raise ValueError(f"Unsupported source_type: {source_type}")
        return self.process_items(items)

    def process_items(self, items: Iterable[TrendItem]) -> int:
        stored = 0
        for item in items:
            enrichments = self._enrich_item(item)
            source_trust = self._source_trust(item)
            corroboration = self._corroboration_count(item)
            scored = score_item(
                item,
                enrichments=enrichments,
                source_trust=source_trust,
                corroboration_count=corroboration,
            )
            summarized = self.summarizer.summarize(scored, enrichments)
            self.repository.upsert_item(summarized)
            if summarized.severity_label == "Critical" and self.alert_queue:
                self.alert_queue.enqueue({"item_id": summarized.item_id})
            stored += 1
        return stored

    def _enrich_item(self, item: TrendItem) -> Dict[str, CVEEnrichment]:
        results: Dict[str, CVEEnrichment] = {}
        for cve in item.cves:
            cached = (
                self.repository.get_enrichment(cve)
                if getattr(self.repository, "get_enrichment", None)
                else None
            )
            if cached:
                results[cve] = cached
                continue
            pieces = []
            for client in (self.nvd_client, self.epss_client, self.kev_client, self.tenable_client):
                try:
                    pieces.append(client.fetch(cve))
                except Exception:
                    continue
            merged = merge_enrichments(cve, pieces)
            results[cve] = merged
            if getattr(self.repository, "upsert_enrichment", None):
                try:
                    self.repository.upsert_enrichment(merged)
                except Exception:
                    pass
        return results

    def _source_trust(self, item: TrendItem) -> float:
        if item.source_name in {"reddit_netsec", "reddit_blueteamsec"}:
            return 0.85
        if item.source_name in {"tenable", "nvd", "kev"}:
            return 0.95
        return 0.70

    def _corroboration_count(self, item: TrendItem) -> int:
        if not getattr(self.repository, "count_corroborating_sources", None):
            return 0
        return self.repository.count_corroborating_sources(item.cves, item.source_name)
