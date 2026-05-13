from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional

import feedparser
import httpx

from cybertrend.models import SourceType, TrendItem
from cybertrend.text import collapse_whitespace, extract_cves


def _parse_date(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.strip()
    try:
        parsed = parsedate_to_datetime(normalized)
    except ValueError:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entry_text(entry, key: str) -> str:
    value = entry.get(key, "")
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return str(value or "")


def _stable_item_id(source_name: str, external_ref: str) -> str:
    digest = hashlib.sha256(f"{source_name}:{external_ref}".encode("utf-8")).hexdigest()[:24]
    return f"rss:{source_name}:{digest}"


class RSSConnector:
    def __init__(self, source_name: str, url: str, http: Optional[httpx.Client] = None):
        self.source_name = source_name
        self.url = url
        self.http = http or httpx.Client(timeout=20)

    def fetch(self) -> List[TrendItem]:
        response = self.http.get(self.url)
        response.raise_for_status()
        parsed = feedparser.parse(response.text)
        items: List[TrendItem] = []
        for entry in parsed.entries:
            title = collapse_whitespace(_entry_text(entry, "title"))
            summary = collapse_whitespace(
                _entry_text(entry, "summary") or _entry_text(entry, "description")
            )
            link = _entry_text(entry, "link")
            published = _entry_text(entry, "published") or _entry_text(entry, "updated")
            external_ref = _entry_text(entry, "id") or link or title
            items.append(
                TrendItem(
                    item_id=_stable_item_id(self.source_name, external_ref),
                    source_type=SourceType.RSS,
                    source_name=self.source_name,
                    title=title,
                    url=link,
                    published_at=_parse_date(published),
                    summary=summary,
                    cves=extract_cves(f"{title} {summary}"),
                    raw=dict(entry),
                )
            )
        return items
