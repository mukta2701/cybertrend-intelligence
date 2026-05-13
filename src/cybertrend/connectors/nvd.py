from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx

from cybertrend.models import CVEEnrichment, SourceType, TrendItem
from cybertrend.text import collapse_whitespace


class NVDClient:
    def __init__(self, api_key: Optional[str] = None, http: Optional[httpx.Client] = None):
        self.api_key = api_key
        self.http = http or httpx.Client(timeout=20)

    def fetch(self, cve: str) -> CVEEnrichment:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        response = self.http.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve.upper()},
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            return CVEEnrichment(cve=cve)
        cve_payload = vulnerabilities[0].get("cve", {})
        metrics = cve_payload.get("metrics", {})
        cvss_base = None
        cvss_severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData", {})
                cvss_base = cvss.get("baseScore")
                cvss_severity = cvss.get("baseSeverity") or entries[0].get("baseSeverity")
                break
        references = []
        refs = cve_payload.get("references") or []
        if isinstance(refs, list):
            for reference in refs:
                url = reference.get("url")
                if url:
                    references.append(url)
        return CVEEnrichment(
            cve=cve_payload.get("id", cve),
            cvss_base=cvss_base,
            cvss_severity=cvss_severity,
            references=references,
            raw=data,
        )

    def fetch_recent(self, hours_back: int = 24) -> List[TrendItem]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        response = self.http.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        items: List[TrendItem] = []
        for vulnerability in data.get("vulnerabilities") or []:
            cve_payload = vulnerability.get("cve", {})
            cve_id = cve_payload.get("id", "")
            if not cve_id:
                continue
            description = ""
            for desc in cve_payload.get("descriptions") or []:
                if desc.get("lang") == "en":
                    description = collapse_whitespace(desc.get("value") or "")
                    break
            metrics = cve_payload.get("metrics", {})
            cvss_base = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []
                if entries:
                    cvss_base = entries[0].get("cvssData", {}).get("baseScore")
                    break
            published_at = now
            published_str = cve_payload.get("published") or ""
            with suppress(ValueError, AttributeError):
                published_at = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00").split(".")[0]
                ).replace(tzinfo=timezone.utc)
            items.append(
                TrendItem(
                    item_id=f"nvd:{cve_id}",
                    source_type=SourceType.NVD,
                    source_name="nvd",
                    title=f"{cve_id} - {description[:120]}" if description else cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=published_at,
                    summary=description,
                    cves=[cve_id],
                    cvss_base=cvss_base,
                    raw=cve_payload,
                )
            )
        return items
