from __future__ import annotations

from typing import Optional

import httpx

from cybertrend.models import CVEEnrichment


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
