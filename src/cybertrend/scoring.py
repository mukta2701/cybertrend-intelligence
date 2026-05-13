from __future__ import annotations

from typing import Mapping

from cybertrend.models import CVEEnrichment, ScoreBreakdown, TrendItem

CRITICALITY_WEIGHTS = {
    "cvss": 0.30,
    "epss_percentile": 0.25,
    "kev": 0.20,
    "tenable_vpr": 0.15,
    "reddit_momentum": 0.10,
}

CONFIDENCE_WEIGHTS = {
    "source_trust": 0.50,
    "cve_evidence_quality": 0.30,
    "cross_source_corroboration": 0.20,
}


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def _best_enrichment(item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> CVEEnrichment:
    best = CVEEnrichment(cve=item.cves[0] if item.cves else "CVE-0000-0000")
    for cve in item.cves:
        enrichment = enrichments.get(cve)
        if not enrichment:
            continue
        if (enrichment.cvss_base or 0) >= (best.cvss_base or 0):
            best = enrichment
        if enrichment.kev:
            best.kev = True
        best.epss_probability = max(best.epss_probability or 0, enrichment.epss_probability or 0)
        best.epss_percentile = max(best.epss_percentile or 0, enrichment.epss_percentile or 0)
        best.tenable_vpr = max(best.tenable_vpr or 0, enrichment.tenable_vpr or 0)
        best.exploit_maturity = best.exploit_maturity or enrichment.exploit_maturity
    return best


def _engagement_signal(item: TrendItem) -> float:
    metrics = item.engagement_metrics
    score_signal = _clamp(metrics.score / 100)
    comments_signal = _clamp(metrics.comments / 50)
    ratio_signal = _clamp(metrics.upvote_ratio or 0)
    velocity_signal = _clamp((metrics.velocity_per_hour or 0) / 25)
    if metrics.velocity_per_hour is not None:
        return (score_signal + comments_signal + ratio_signal + velocity_signal) / 4
    return (score_signal + comments_signal + ratio_signal) / 3


def _evidence_quality(item: TrendItem, best: CVEEnrichment) -> float:
    if not item.cves:
        return 0.0
    score = 0.35
    if best.cvss_base is not None or item.cvss_base is not None:
        score += 0.25
    if best.epss_percentile is not None or item.epss_percentile is not None:
        score += 0.20
    if best.kev or item.kev_flag:
        score += 0.15
    if item.exploit_evidence:
        score += 0.05
    return _clamp(score)


def _strong_exploit_evidence(item: TrendItem, best: CVEEnrichment) -> bool:
    evidence = " ".join(
        [
            item.exploit_evidence or "",
            best.exploit_maturity or "",
            item.summary or "",
            item.title or "",
        ]
    ).lower()
    indicators = ["active exploitation", "exploited in the wild", "public exploit", "functional"]
    return any(indicator in evidence for indicator in indicators)


def score_item(
    item: TrendItem,
    enrichments: Mapping[str, CVEEnrichment],
    source_trust: float,
    corroboration_count: int,
) -> TrendItem:
    best = _best_enrichment(item, enrichments)
    cvss_base = best.cvss_base if best.cvss_base is not None else item.cvss_base
    epss_probability = (
        best.epss_probability if best.epss_probability is not None else item.epss_probability
    )
    epss_percentile = (
        best.epss_percentile if best.epss_percentile is not None else item.epss_percentile
    )
    tenable_vpr = best.tenable_vpr if best.tenable_vpr is not None else item.tenable_vpr
    kev_flag = bool(best.kev or item.kev_flag)

    criticality_inputs = {
        "cvss": _clamp((cvss_base or 0) / 10),
        "epss_percentile": _clamp(epss_percentile or 0),
        "kev": 1.0 if kev_flag else 0.0,
        "tenable_vpr": _clamp((tenable_vpr or 0) / 10),
        "reddit_momentum": _engagement_signal(item),
    }
    criticality_contributions = {
        key: criticality_inputs[key] * weight * 100 for key, weight in CRITICALITY_WEIGHTS.items()
    }
    criticality_score = round(sum(criticality_contributions.values()), 2)

    confidence_inputs = {
        "source_trust": _clamp(source_trust),
        "cve_evidence_quality": _evidence_quality(item, best),
        "cross_source_corroboration": _clamp(corroboration_count / 2),
    }
    confidence_contributions = {
        key: confidence_inputs[key] * weight * 100 for key, weight in CONFIDENCE_WEIGHTS.items()
    }
    confidence_score = round(sum(confidence_contributions.values()), 2)

    if criticality_score >= 85 or (kev_flag and _strong_exploit_evidence(item, best)):
        severity = "Critical"
    elif criticality_score >= 70:
        severity = "High"
    elif criticality_score >= 50:
        severity = "Medium"
    else:
        severity = "Low"

    reasons = []
    if kev_flag:
        reasons.append("CISA KEV indicates known exploitation.")
    if epss_percentile is not None:
        reasons.append(f"EPSS percentile is {epss_percentile:.2f}.")
    if item.engagement_metrics.score or item.engagement_metrics.comments:
        reasons.append("Community momentum contributed to prioritization.")

    return item.model_copy(
        update={
            "cvss_base": cvss_base,
            "epss_probability": epss_probability,
            "epss_percentile": epss_percentile,
            "kev_flag": kev_flag,
            "tenable_vpr": tenable_vpr,
            "criticality_score": criticality_score,
            "confidence_score": confidence_score,
            "severity_label": severity,
            "score_breakdown": ScoreBreakdown(
                criticality_inputs=criticality_inputs,
                criticality_weights=CRITICALITY_WEIGHTS.copy(),
                criticality_contributions=criticality_contributions,
                confidence_inputs=confidence_inputs,
                confidence_weights=CONFIDENCE_WEIGHTS.copy(),
                confidence_contributions=confidence_contributions,
                reasons=reasons,
            ),
        }
    )
