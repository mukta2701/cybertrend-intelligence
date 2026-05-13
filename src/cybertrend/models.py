from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class SourceType(str, Enum):
    REDDIT = "reddit"
    RSS = "rss"
    NVD = "nvd"
    KEV = "kev"
    NEWSLETTER = "newsletter"


class SeverityLabel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class EngagementMetrics(BaseModel):
    score: int = 0
    comments: int = 0
    upvote_ratio: Optional[float] = None
    shares: int = 0
    velocity_per_hour: Optional[float] = None


class ScoreBreakdown(BaseModel):
    criticality_inputs: Dict[str, float] = Field(default_factory=dict)
    criticality_weights: Dict[str, float] = Field(default_factory=dict)
    criticality_contributions: Dict[str, float] = Field(default_factory=dict)
    confidence_inputs: Dict[str, float] = Field(default_factory=dict)
    confidence_weights: Dict[str, float] = Field(default_factory=dict)
    confidence_contributions: Dict[str, float] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)


class CVEEnrichment(BaseModel):
    cve: str
    cvss_base: Optional[float] = None
    cvss_severity: Optional[str] = None
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    tenable_vpr: Optional[float] = None
    exploit_maturity: Optional[str] = None
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    required_action: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        return value.upper()


class TrendItem(BaseModel):
    item_id: str
    source_type: SourceType
    source_name: str
    community: Optional[str] = None
    title: str
    url: str
    published_at: datetime
    summary: str = ""
    what_went_wrong: str = ""
    why_this_matters_now: str = ""
    cves: List[str] = Field(default_factory=list)
    cvss_base: Optional[float] = None
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_flag: bool = False
    tenable_vpr: Optional[float] = None
    exploit_evidence: Optional[str] = None
    engagement_metrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    criticality_score: float = 0
    confidence_score: float = 0
    severity_label: str = SeverityLabel.LOW.value
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    llm_analysis: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("cves")
    @classmethod
    def normalize_cves(cls, values: List[str]) -> List[str]:
        seen: List[str] = []
        for value in values:
            cve = value.upper()
            if cve not in seen:
                seen.append(cve)
        return seen


class SourceJob(BaseModel):
    source_type: SourceType
    source_name: str
    community: Optional[str] = None
    url: Optional[str] = None
    requested_at: datetime


class SourcePolicyEntry(BaseModel):
    source_name: str
    source_type: SourceType
    enabled: bool = True
    trust_tier: float = 0.7
    weight: float = 1.0
    allowlist: List[str] = Field(default_factory=list)
    denylist: List[str] = Field(default_factory=list)


class SourcePolicy(BaseModel):
    sources: List[SourcePolicyEntry] = Field(default_factory=list)


class SourceHealth(BaseModel):
    source_name: str
    source_type: SourceType
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    last_error: Optional[str] = None
    lag_seconds: Optional[int] = None
    consecutive_failures: int = 0
    rate_limited_until: Optional[datetime] = None


class DigestSection(BaseModel):
    name: str
    severity: str
    items: List[TrendItem] = Field(default_factory=list)


class DigestPayload(BaseModel):
    digest_date: date
    sections: List[DigestSection] = Field(default_factory=list)
    source_quality_footer: Optional[str] = None


class RenderedEmail(BaseModel):
    subject: str
    html: str
    text: str


class RawItem(BaseModel):
    source_type: SourceType
    source_name: str
    external_id: str
    url: str
    title: str
    published_at: datetime
    body: str = ""
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
