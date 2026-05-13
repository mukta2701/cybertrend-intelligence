from __future__ import annotations

from typing import Iterable, List

from cybertrend.models import CVEEnrichment


def merge_enrichments(cve: str, enrichments: Iterable[CVEEnrichment]) -> CVEEnrichment:
    merged = CVEEnrichment(cve=cve)
    references: List[str] = []
    raw = {}
    for enrichment in enrichments:
        if enrichment.cvss_base is not None:
            merged.cvss_base = max(merged.cvss_base or 0, enrichment.cvss_base)
        merged.cvss_severity = merged.cvss_severity or enrichment.cvss_severity
        if enrichment.epss_probability is not None:
            merged.epss_probability = max(merged.epss_probability or 0, enrichment.epss_probability)
        if enrichment.epss_percentile is not None:
            merged.epss_percentile = max(merged.epss_percentile or 0, enrichment.epss_percentile)
        merged.kev = merged.kev or enrichment.kev
        if enrichment.tenable_vpr is not None:
            merged.tenable_vpr = max(merged.tenable_vpr or 0, enrichment.tenable_vpr)
        merged.exploit_maturity = merged.exploit_maturity or enrichment.exploit_maturity
        merged.vendor_project = merged.vendor_project or enrichment.vendor_project
        merged.product = merged.product or enrichment.product
        merged.vulnerability_name = merged.vulnerability_name or enrichment.vulnerability_name
        merged.required_action = merged.required_action or enrichment.required_action
        for reference in enrichment.references:
            if reference not in references:
                references.append(reference)
        if enrichment.raw:
            raw[enrichment.cve] = enrichment.raw
    merged.references = references
    merged.raw = raw
    return merged
