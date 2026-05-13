from __future__ import annotations

from typing import Optional

import httpx

from cybertrend.models import CVEEnrichment


class TenableVPRClient:
    """Optional Tenable vulnerability intelligence adapter.

    Tenable deployments vary by product and entitlement; this adapter keeps the VPR field optional
    and isolated so scoring can renormalize when credentials are absent.
    """

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        http: Optional[httpx.Client] = None,
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.http = http or httpx.Client(timeout=20)

    def fetch(self, cve: str) -> CVEEnrichment:
        if not self.access_key or not self.secret_key:
            return CVEEnrichment(cve=cve)
        response = self.http.get(
            "https://cloud.tenable.com/workbenches/vulnerabilities",
            params={"cve": cve.upper()},
            headers={"X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}"},
        )
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities") or []
        vpr = None
        if vulnerabilities:
            first = vulnerabilities[0]
            vpr = first.get("vpr_score") or first.get("vprScore")
        return CVEEnrichment(
            cve=cve, tenable_vpr=float(vpr) if vpr is not None else None, raw=payload
        )
