from __future__ import annotations

import re
from typing import List

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers in first-seen order."""
    seen: List[str] = []
    for match in CVE_PATTERN.findall(text or ""):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()
