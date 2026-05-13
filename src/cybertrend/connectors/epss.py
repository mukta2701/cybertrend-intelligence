from __future__ import annotations

from typing import Optional

import httpx

from cybertrend.models import CVEEnrichment


class EPSSClient:
    def __init__(self, http: Optional[httpx.Client] = None):
        self.http = http or httpx.Client(timeout=20)

    def fetch(self, cve: str) -> CVEEnrichment:
        response = self.http.get("https://api.first.org/data/v1/epss", params={"cve": cve.upper()})
        response.raise_for_status()
        data = response.json()
        rows = data.get("data") or []
        if not rows:
            return CVEEnrichment(cve=cve)
        row = rows[0]
        return CVEEnrichment(
            cve=row.get("cve", cve),
            epss_probability=float(row["epss"]) if row.get("epss") is not None else None,
            epss_percentile=float(row["percentile"]) if row.get("percentile") is not None else None,
            raw=data,
        )
