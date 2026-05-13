from __future__ import annotations

from typing import Dict, Optional

import httpx

from cybertrend.models import CVEEnrichment

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient:
    def __init__(self, http: Optional[httpx.Client] = None, url: str = KEV_URL):
        self.http = http or httpx.Client(timeout=20)
        self.url = url
        self._catalog: Optional[Dict[str, dict]] = None

    def _load_catalog(self) -> Dict[str, dict]:
        if self._catalog is not None:
            return self._catalog
        response = self.http.get(self.url)
        response.raise_for_status()
        data = response.json()
        self._catalog = {
            row.get("cveID", "").upper(): row
            for row in data.get("vulnerabilities", [])
            if row.get("cveID")
        }
        return self._catalog

    def fetch(self, cve: str) -> CVEEnrichment:
        row = self._load_catalog().get(cve.upper())
        if not row:
            return CVEEnrichment(cve=cve, kev=False)
        return CVEEnrichment(
            cve=cve,
            kev=True,
            vendor_project=row.get("vendorProject"),
            product=row.get("product"),
            vulnerability_name=row.get("vulnerabilityName"),
            required_action=row.get("requiredAction"),
            raw=row,
        )
