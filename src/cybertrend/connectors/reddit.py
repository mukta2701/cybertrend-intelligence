from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

import httpx

from cybertrend.models import EngagementMetrics, SourceType, TrendItem
from cybertrend.text import collapse_whitespace, extract_cves


class RedditClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        user_agent: str,
        http: Optional[httpx.Client] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_agent = user_agent
        self.http = http or httpx.Client(timeout=20)
        self._access_token: Optional[str] = None

    def _token(self) -> str:
        if self._access_token:
            return self._access_token
        response = self.http.post(
            "https://www.reddit.com/api/v1/access_token",
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            headers={"User-Agent": self.user_agent},
        )
        response.raise_for_status()
        self._access_token = str(response.json()["access_token"])
        return self._access_token

    def fetch_subreddit(self, subreddit: str, limit: int = 50) -> List[TrendItem]:
        token = self._token()
        response = self.http.get(
            f"https://oauth.reddit.com/r/{subreddit}/new",
            params={"limit": limit, "raw_json": 1},
            headers={"Authorization": f"Bearer {token}", "User-Agent": self.user_agent},
        )
        response.raise_for_status()
        children = response.json().get("data", {}).get("children", [])
        items: List[TrendItem] = []
        for child in children:
            data = child.get("data", {})
            body = collapse_whitespace(data.get("selftext") or "")
            title = collapse_whitespace(data.get("title") or "")
            text = f"{title} {body}"
            published_at = datetime.fromtimestamp(data.get("created_utc", 0), tz=timezone.utc)
            items.append(
                TrendItem(
                    item_id=f"reddit:{data.get('id')}",
                    source_type=SourceType.REDDIT,
                    source_name="reddit",
                    community=data.get("subreddit", subreddit),
                    title=title,
                    url=data.get("url") or f"https://reddit.com{data.get('permalink', '')}",
                    published_at=published_at,
                    summary=body,
                    cves=extract_cves(text),
                    engagement_metrics=EngagementMetrics(
                        score=int(data.get("score") or 0),
                        comments=int(data.get("num_comments") or 0),
                        upvote_ratio=data.get("upvote_ratio"),
                    ),
                    raw=data,
                )
            )
        return items
