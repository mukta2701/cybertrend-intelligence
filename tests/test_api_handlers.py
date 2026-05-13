from datetime import datetime, timezone

from fastapi.testclient import TestClient

from cybertrend.api import create_app
from cybertrend.models import DigestPayload, DigestSection, EngagementMetrics, SourceType, TrendItem


class FakePipeline:
    def __init__(self):
        self.manual_runs = 0

    def trigger_manual_run(self):
        self.manual_runs += 1
        return {"run_id": "manual-1", "queued_jobs": 5}

    def list_items(self, severity=None, source=None, since=None, limit=50, cursor=None):
        return {
            "items": [
                TrendItem(
                    item_id="item-1",
                    source_type=SourceType.REDDIT,
                    source_name="reddit",
                    community="netsec",
                    title="CVE-2026-12345 exploited",
                    url="https://example.com",
                    published_at=datetime(2026, 5, 13, 7, 30, tzinfo=timezone.utc),
                    summary="Active exploitation.",
                    what_went_wrong="Remote code execution.",
                    cves=["CVE-2026-12345"],
                    engagement_metrics=EngagementMetrics(score=10, comments=2, upvote_ratio=0.9),
                    severity_label="Critical",
                )
            ],
            "next_cursor": None,
        }

    def get_digest(self, digest_date):
        return DigestPayload(
            digest_date=digest_date,
            sections=[DigestSection(name="Critical - Act Now", severity="Critical", items=[])],
        )

    def get_source_health(self):
        return {"sources": []}

    def update_source_policy(self, policy):
        return policy

    def explain_score(self, item_id):
        return {"item_id": item_id, "score_breakdown": {"criticality": 91}}


def test_api_exposes_required_internal_endpoints():
    fake = FakePipeline()
    client = TestClient(create_app(pipeline=fake, api_key="test-key"))
    headers = {"x-api-key": "test-key"}

    assert client.post("/runs/manual", headers=headers).json()["queued_jobs"] == 5
    assert (
        client.get("/items?severity=Critical", headers=headers).json()["items"][0]["item_id"]
        == "item-1"
    )
    assert client.get("/digests/2026-05-13", headers=headers).json()["digest_date"] == "2026-05-13"
    assert client.get("/sources/health", headers=headers).json() == {"sources": []}
    assert client.put("/sources/policy", headers=headers, json={"sources": []}).status_code == 200
    assert client.get("/scores/explain/item-1", headers=headers).json()["item_id"] == "item-1"


def test_api_rejects_requests_without_api_key():
    client = TestClient(create_app(pipeline=FakePipeline(), api_key="test-key"))

    response = client.post("/runs/manual")

    assert response.status_code == 401
