from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Iterable, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cybertrend.models import TrendItem

TRACKING_PREFIXES = ("utm_",)
TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "igshid", "ref", "source"}


def canonicalize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"

    path = posixpath.normpath(parsed.path or "/")
    if path == ".":
        path = "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in TRACKING_KEYS or any(
            lowered.startswith(prefix) for prefix in TRACKING_PREFIXES
        ):
            continue
        query_items.append((key, value))
    query = urlencode(sorted(query_items))
    return urlunsplit((scheme, netloc, path, query, ""))


def normalized_title(title: str) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", (title or "").lower()).strip()
    return re.sub(r"\s+", " ", text)


def dedupe_key(item: TrendItem) -> str:
    if item.cves:
        return "cve:" + ",".join(sorted(item.cves))
    url = canonicalize_url(item.url)
    if url:
        return "url:" + hashlib.sha256(url.encode("utf-8")).hexdigest()
    return "title:" + hashlib.sha256(normalized_title(item.title).encode("utf-8")).hexdigest()


def shared_cve_count(items: Iterable[TrendItem]) -> int:
    cves: List[str] = []
    for item in items:
        for cve in item.cves:
            if cve not in cves:
                cves.append(cve)
    return len(cves)
