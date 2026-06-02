from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from cybertrend.db.models import (
    AlertDeliveryRecord,
    CVEEnrichmentRecord,
    DigestRunRecord,
    SourceHealthRecord,
    SourcePolicyRecord,
    TrendItemRecord,
)
from cybertrend.dedupe import dedupe_key
from cybertrend.models import (
    CVEEnrichment,
    DigestPayload,
    DigestSection,
    SourceHealth,
    SourcePolicy,
    SourceType,
    TrendItem,
)


def _item_to_record(item: TrendItem) -> Dict[str, Any]:
    return {
        "item_id": item.item_id,
        "dedupe_key": dedupe_key(item),
        "source_type": item.source_type.value,
        "source_name": item.source_name,
        "community": item.community,
        "title": item.title,
        "url": item.url,
        "published_at": item.published_at,
        "summary": item.summary,
        "what_went_wrong": item.what_went_wrong,
        "why_this_matters_now": item.why_this_matters_now,
        "cves": item.cves,
        "cvss_base": item.cvss_base,
        "epss_probability": item.epss_probability,
        "epss_percentile": item.epss_percentile,
        "kev_flag": item.kev_flag,
        "tenable_vpr": item.tenable_vpr,
        "exploit_evidence": item.exploit_evidence,
        "engagement_metrics": item.engagement_metrics.model_dump(),
        "criticality_score": item.criticality_score,
        "confidence_score": item.confidence_score,
        "severity_label": item.severity_label,
        "score_breakdown": item.score_breakdown.model_dump(),
        "llm_analysis": item.llm_analysis,
        "raw": item.raw,
    }


def _record_to_item(record: TrendItemRecord) -> TrendItem:
    payload = {
        "item_id": record.item_id,
        "source_type": record.source_type,
        "source_name": record.source_name,
        "community": record.community,
        "title": record.title,
        "url": record.url,
        "published_at": record.published_at,
        "summary": record.summary,
        "what_went_wrong": record.what_went_wrong,
        "why_this_matters_now": record.why_this_matters_now,
        "cves": record.cves,
        "cvss_base": record.cvss_base,
        "epss_probability": record.epss_probability,
        "epss_percentile": record.epss_percentile,
        "kev_flag": record.kev_flag,
        "tenable_vpr": record.tenable_vpr,
        "exploit_evidence": record.exploit_evidence,
        "engagement_metrics": record.engagement_metrics,
        "criticality_score": record.criticality_score,
        "confidence_score": record.confidence_score,
        "severity_label": record.severity_label,
        "score_breakdown": record.score_breakdown,
        "llm_analysis": record.llm_analysis if isinstance(record.llm_analysis, dict) else None,
        "raw": record.raw,
    }
    return TrendItem.model_validate(payload)


class Repository:
    def __init__(self, session: Any):
        self.session = session

    def upsert_item(self, item: TrendItem) -> None:
        values = _item_to_record(item)
        statement = insert(TrendItemRecord).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=[TrendItemRecord.item_id],
            set_={
                **{key: value for key, value in values.items() if key != "item_id"},
                "updated_at": func.now(),
            },
        )
        self.session.execute(statement)
        self.session.commit()

    def list_items(
        self,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        statement = select(TrendItemRecord)
        if severity:
            statement = statement.where(TrendItemRecord.severity_label == severity)
        if source:
            statement = statement.where(TrendItemRecord.source_name == source)
        if since:
            statement = statement.where(TrendItemRecord.published_at >= since)
        if cursor:
            try:
                statement = statement.where(
                    TrendItemRecord.published_at < datetime.fromisoformat(cursor)
                )
            except ValueError:
                pass  # invalid cursor ignored — return from beginning
        statement = statement.order_by(TrendItemRecord.published_at.desc()).limit(limit + 1)
        records = list(self.session.scalars(statement))
        next_cursor = None
        if len(records) > limit:
            next_cursor = records[-1].published_at.isoformat()
            records = records[:limit]
        return {
            "items": [_record_to_item(record) for record in records],
            "next_cursor": next_cursor,
        }

    def get_item(self, item_id: str) -> Optional[TrendItem]:
        record = self.session.get(TrendItemRecord, item_id)
        return _record_to_item(record) if record else None

    def get_digest(self, digest_date: date) -> Optional[DigestPayload]:
        record = self.session.get(DigestRunRecord, digest_date)
        if not record:
            return None
        return DigestPayload.model_validate(record.payload)

    def save_digest(self, payload: DigestPayload, *, sent_at: Optional[datetime] = None) -> None:
        values = {
            "digest_date": payload.digest_date,
            "payload": payload.model_dump(mode="json"),
            "sent_at": sent_at,
        }
        stmt = insert(DigestRunRecord).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[DigestRunRecord.digest_date],
            set_={k: v for k, v in values.items() if k != "digest_date"},
        )
        self.session.execute(stmt)
        self.session.commit()

    def get_items_by_ingestion_date(self, ingestion_date: date) -> List[TrendItem]:
        start = datetime(
            ingestion_date.year, ingestion_date.month, ingestion_date.day, tzinfo=timezone.utc
        )
        end = start + timedelta(days=1)
        records = list(
            self.session.scalars(
                select(TrendItemRecord)
                .where(TrendItemRecord.created_at >= start)
                .where(TrendItemRecord.created_at < end)
            )
        )
        return [_record_to_item(r) for r in records]

    def build_digest_from_items(self, digest_date: date) -> DigestPayload:
        start = datetime(
            digest_date.year, digest_date.month, digest_date.day, tzinfo=timezone.utc
        )
        end = start + timedelta(days=1)
        records = list(
            self.session.scalars(
                select(TrendItemRecord)
                .where(TrendItemRecord.updated_at >= start)
                .where(TrendItemRecord.updated_at < end)
                .order_by(TrendItemRecord.criticality_score.desc())
            )
        )
        buckets: Dict[str, List[TrendItem]] = {"Critical": [], "High": [], "Medium": []}
        for record in records:
            item = _record_to_item(record)
            if item.severity_label in buckets:
                buckets[item.severity_label].append(item)
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(
                    name="Critical Threats",
                    severity="Critical",
                    items=buckets["Critical"],
                ),
                DigestSection(
                    name="High Priority",
                    severity="High",
                    items=buckets["High"],
                ),
                DigestSection(name="Medium Risk", severity="Medium", items=buckets["Medium"]),
            ],
        )

    def get_enrichment(self, cve: str) -> Optional[CVEEnrichment]:
        record = self.session.get(CVEEnrichmentRecord, cve)
        if record is None:
            return None
        updated = record.updated_at
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - updated > timedelta(hours=24):
            return None
        return CVEEnrichment(
            cve=record.cve,
            cvss_base=record.cvss_base,
            cvss_severity=record.cvss_severity,
            epss_probability=record.epss_probability,
            epss_percentile=record.epss_percentile,
            kev=record.kev,
            tenable_vpr=record.tenable_vpr,
            exploit_maturity=record.exploit_maturity,
            vendor_project=record.vendor_project,
            product=record.product,
            vulnerability_name=record.vulnerability_name,
            required_action=record.required_action,
            references=list(record.references or []),
            raw=dict(record.raw or {}),
        )

    def upsert_enrichment(self, enrichment: CVEEnrichment) -> None:
        values = {
            "cve": enrichment.cve,
            "cvss_base": enrichment.cvss_base,
            "cvss_severity": enrichment.cvss_severity,
            "epss_probability": enrichment.epss_probability,
            "epss_percentile": enrichment.epss_percentile,
            "kev": enrichment.kev,
            "tenable_vpr": enrichment.tenable_vpr,
            "exploit_maturity": enrichment.exploit_maturity,
            "vendor_project": enrichment.vendor_project,
            "product": enrichment.product,
            "vulnerability_name": enrichment.vulnerability_name,
            "required_action": enrichment.required_action,
            "references": enrichment.references,
            "raw": enrichment.raw,
        }
        stmt = insert(CVEEnrichmentRecord).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CVEEnrichmentRecord.cve],
            set_={k: v for k, v in values.items() if k != "cve"},
        )
        self.session.execute(stmt)
        self.session.commit()

    def get_source_health(self) -> List[SourceHealth]:
        records = list(
            self.session.scalars(
                select(SourceHealthRecord).order_by(SourceHealthRecord.source_name)
            )
        )
        return [
            SourceHealth(
                source_name=record.source_name,
                source_type=SourceType(record.source_type),
                last_success_at=record.last_success_at,
                last_error_at=record.last_error_at,
                last_error=record.last_error,
                lag_seconds=record.lag_seconds,
                consecutive_failures=record.consecutive_failures,
                rate_limited_until=record.rate_limited_until,
            )
            for record in records
        ]

    def upsert_source_health(
        self,
        source_name: str,
        source_type: str,
        *,
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        existing = self.session.get(SourceHealthRecord, source_name)
        if existing:
            if success:
                existing.last_success_at = now
                existing.consecutive_failures = 0
                existing.last_error = None
            else:
                existing.last_error_at = now
                existing.last_error = error
                existing.consecutive_failures = (existing.consecutive_failures or 0) + 1
        else:
            record = SourceHealthRecord(
                source_name=source_name,
                source_type=source_type,
                last_success_at=now if success else None,
                last_error_at=None if success else now,
                last_error=None if success else error,
                consecutive_failures=0 if success else 1,
            )
            self.session.add(record)
        self.session.commit()

    def update_source_policy(self, policy: SourcePolicy) -> None:
        for entry in policy.sources:
            values = entry.model_dump()
            values["source_type"] = entry.source_type.value
            statement = insert(SourcePolicyRecord).values(**values)
            statement = statement.on_conflict_do_update(
                index_elements=[SourcePolicyRecord.source_name],
                set_={key: value for key, value in values.items() if key != "source_name"},
            )
            self.session.execute(statement)
        self.session.commit()

    def explain_score(self, item_id: str) -> Dict[str, Any]:
        item = self.get_item(item_id)
        return {
            "item_id": item_id,
            "score_breakdown": item.score_breakdown.model_dump() if item else None,
        }

    def count_corroborating_sources(self, cves: List[str], current_source: str) -> int:
        if not cves:
            return 0
        records = list(
            self.session.scalars(
                select(TrendItemRecord).where(TrendItemRecord.source_name != current_source)
            )
        )
        sources = set()
        wanted = set(cves)
        for record in records:
            if wanted.intersection(set(record.cves or [])):
                sources.add(record.source_name)
        return len(sources)

    def alert_already_sent(self, item_id: str, delivery_type: str) -> bool:
        statement = select(AlertDeliveryRecord).where(
            AlertDeliveryRecord.item_id == item_id,
            AlertDeliveryRecord.delivery_type == delivery_type,
        )
        return self.session.scalar(statement) is not None

    def record_alert_delivery(
        self, item_id: str, delivery_type: str, provider_message_id: Optional[str] = None
    ) -> None:
        self.session.add(
            AlertDeliveryRecord(
                item_id=item_id,
                delivery_type=delivery_type,
                provider_message_id=provider_message_id,
            )
        )
        self.session.commit()

    def refresh_source_quality(self) -> Dict[str, Any]:
        records = list(self.session.scalars(select(SourcePolicyRecord)))
        updated = 0
        for record in records:
            record.updated_at = datetime.now(timezone.utc)
            updated += 1
        self.session.commit()
        return {"updated_sources": updated}
