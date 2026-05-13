from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from cybertrend.db.models import (
    AlertDeliveryRecord,
    DigestRunRecord,
    SourceHealthRecord,
    SourcePolicyRecord,
    TrendItemRecord,
)
from cybertrend.dedupe import dedupe_key
from cybertrend.models import (
    DigestPayload,
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
            set_={key: value for key, value in values.items() if key != "item_id"},
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
            statement = statement.where(
                TrendItemRecord.published_at < datetime.fromisoformat(cursor)
            )
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
