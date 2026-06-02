from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
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


@dataclass
class IngestionStats:
    fetched_items: int = 0
    processed_items: int = 0
    stored_items: int = 0
    skipped_summaries: int = 0
    limited_items: int = 0


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
        max_items_per_source: int = 25,
        max_nvd_items: int = 50,
    ):
        self.repository = repository
        self.alert_queue = alert_queue
        self.reddit_client = reddit_client
        self.nvd_client = nvd_client or NVDClient()
        self.epss_client = epss_client or EPSSClient()
        self.kev_client = kev_client or KEVClient()
        self.tenable_client = tenable_client or TenableVPRClient()
        self.summarizer = summarizer or HybridSummaryProvider()
        self.max_items_per_source = max_items_per_source
        self.max_nvd_items = max_nvd_items
        self.last_stats = IngestionStats()

    def process_job(self, job: dict) -> int:
        source_type = job.get("source_type", "unknown")
        source_name = job.get("source_name", "unknown")
        items: List[TrendItem] = []
        try:
            if source_type == "reddit":
                if not self.reddit_client:
                    raise RuntimeError("Reddit client is not configured")
                items = self.reddit_client.fetch_subreddit(job["community"])
            elif source_type == "rss":
                rss_connector = RSSConnector(source_name=source_name, url=job["url"])
                items = rss_connector.fetch()
            elif source_type == "nvd":
                hours_back = int(job.get("hours_back", 24))
                items = self.nvd_client.fetch_recent(hours_back=hours_back)
            else:
                raise ValueError(f"Unsupported source_type: {source_type}")
            fetched_items = len(items)
            limited_items = self._limit_items(items, source_type)
            stats = self._process_items_with_stats(limited_items)
            stats.fetched_items = fetched_items
            stats.limited_items = max(fetched_items - stats.processed_items, 0)
            self.last_stats = stats
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(source_name, source_type, success=True)
            return stats.stored_items
        except Exception as exc:
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(
                    source_name, source_type, success=False, error=str(exc)
                )
            raise

    def process_items(self, items: Iterable[TrendItem]) -> int:
        item_list = list(items)
        stats = self._process_items_with_stats(item_list)
        stats.fetched_items = len(item_list)
        self.last_stats = stats
        return stats.stored_items

    def _process_items_with_stats(self, items: List[TrendItem]) -> IngestionStats:
        stats = IngestionStats(processed_items=len(items))
        for item in items:
            existing = (
                self.repository.get_item(item.item_id)
                if getattr(self.repository, "get_item", None)
                else None
            )
            enrichments = self._enrich_item(item)
            source_trust = self._source_trust(item)
            corroboration = self._corroboration_count(item)
            scored = score_item(
                item,
                enrichments=enrichments,
                source_trust=source_trust,
                corroboration_count=corroboration,
            )
            if self._can_reuse_summary(existing, item) and existing is not None:
                summarized = self._reuse_summary(scored, existing)
                stats.skipped_summaries += 1
            else:
                summarized = self.summarizer.summarize(scored, enrichments)
            self.repository.upsert_item(summarized)
            if summarized.severity_label == "Critical" and self.alert_queue:
                self.alert_queue.enqueue({"item_id": summarized.item_id})
            stats.stored_items += 1
        return stats

    def _limit_items(self, items: List[TrendItem], source_type: str) -> List[TrendItem]:
        limit = self.max_nvd_items if source_type == "nvd" else self.max_items_per_source
        if limit <= 0 or len(items) <= limit:
            return items
        return sorted(items, key=self._pre_enrichment_priority, reverse=True)[:limit]

    def _pre_enrichment_priority(self, item: TrendItem):
        return (
            1 if item.kev_flag else 0,
            item.cvss_base or 0,
            item.epss_percentile or 0,
            item.engagement_metrics.score,
            item.engagement_metrics.comments,
            item.published_at,
        )

    def _can_reuse_summary(self, existing: Optional[TrendItem], incoming: TrendItem) -> bool:
        if not existing or not existing.llm_analysis:
            return False
        return (
            existing.title == incoming.title
            and existing.url == incoming.url
            and existing.cves == incoming.cves
            and existing.raw == incoming.raw
        )

    def _reuse_summary(self, item: TrendItem, existing: TrendItem) -> TrendItem:
        return item.model_copy(
            update={
                "summary": existing.summary,
                "what_went_wrong": existing.what_went_wrong,
                "why_this_matters_now": existing.why_this_matters_now,
                "llm_analysis": existing.llm_analysis,
            }
        )

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
                with suppress(Exception):
                    self.repository.upsert_enrichment(merged)
        return results

    def _source_trust(self, item: TrendItem) -> float:
        if item.source_name in {"tenable", "nvd", "kev"}:
            return 0.95
        if item.source_name in {"krebsonsecurity", "sans_isc", "darkreading"}:
            return 0.85
        return 0.70

    def _corroboration_count(self, item: TrendItem) -> int:
        if not getattr(self.repository, "count_corroborating_sources", None):
            return 0
        return self.repository.count_corroborating_sources(item.cves, item.source_name)
