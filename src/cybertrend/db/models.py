from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cybertrend.db.base import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RawItemRecord(Base, TimestampMixin):
    __tablename__ = "raw_items"
    __table_args__ = (
        UniqueConstraint("source_name", "external_id", name="uq_raw_source_external"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class TrendItemRecord(Base, TimestampMixin):
    __tablename__ = "trend_items"

    item_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    community: Mapped[Optional[str]] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    what_went_wrong: Mapped[str] = mapped_column(Text, nullable=False, default="")
    why_this_matters_now: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cves: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    cvss_base: Mapped[Optional[float]] = mapped_column(Float)
    epss_probability: Mapped[Optional[float]] = mapped_column(Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)
    kev_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tenable_vpr: Mapped[Optional[float]] = mapped_column(Float)
    exploit_evidence: Mapped[Optional[str]] = mapped_column(Text)
    engagement_metrics: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    criticality_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    severity_label: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    score_breakdown: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    llm_analysis: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True, default=None)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class CVEEnrichmentRecord(Base, TimestampMixin):
    __tablename__ = "cve_enrichments"

    cve: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_base: Mapped[Optional[float]] = mapped_column(Float)
    cvss_severity: Mapped[Optional[str]] = mapped_column(String(32))
    epss_probability: Mapped[Optional[float]] = mapped_column(Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tenable_vpr: Mapped[Optional[float]] = mapped_column(Float)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(128))
    vendor_project: Mapped[Optional[str]] = mapped_column(String(256))
    product: Mapped[Optional[str]] = mapped_column(String(256))
    vulnerability_name: Mapped[Optional[str]] = mapped_column(Text)
    required_action: Mapped[Optional[str]] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class SourcePolicyRecord(Base, TimestampMixin):
    __tablename__ = "source_policies"

    source_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    trust_tier: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    allowlist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    denylist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class SourceHealthRecord(Base, TimestampMixin):
    __tablename__ = "source_health"

    source_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    lag_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rate_limited_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AlertDeliveryRecord(Base, TimestampMixin):
    __tablename__ = "alert_deliveries"
    __table_args__ = (UniqueConstraint("item_id", "delivery_type", name="uq_alert_item_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    delivery_type: Mapped[str] = mapped_column(String(32), nullable=False)
    delivered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    provider_message_id: Mapped[Optional[str]] = mapped_column(String(256))


class DigestRunRecord(Base, TimestampMixin):
    __tablename__ = "digest_runs"

    digest_date: Mapped[datetime] = mapped_column(Date, primary_key=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class SourceQualityMetricRecord(Base, TimestampMixin):
    __tablename__ = "source_quality_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    useful_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    noisy_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    computed_weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
