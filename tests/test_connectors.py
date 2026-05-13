from datetime import datetime, timezone

import httpx

from cybertrend.connectors.epss import EPSSClient
from cybertrend.connectors.kev import KEVClient
from cybertrend.connectors.nvd import NVDClient
from cybertrend.connectors.reddit import RedditClient
from cybertrend.connectors.rss import RSSConnector


def test_nvd_client_normalizes_cvss_from_cve_api_payload():
    def handler(request):
        assert "cveId=CVE-2026-12345" in str(request.url)
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                        }
                    }
                ]
            },
        )

    client = NVDClient(http=httpx.Client(transport=httpx.MockTransport(handler)))

    enrichment = client.fetch("CVE-2026-12345")

    assert enrichment.cve == "CVE-2026-12345"
    assert enrichment.cvss_base == 9.8


def test_epss_client_parses_probability_and_percentile():
    client = EPSSClient(
        http=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "cve": "CVE-2026-12345",
                                "epss": "0.840000",
                                "percentile": "0.960000",
                            }
                        ]
                    },
                )
            )
        )
    )

    enrichment = client.fetch("CVE-2026-12345")

    assert enrichment.epss_probability == 0.84
    assert enrichment.epss_percentile == 0.96


def test_kev_client_flags_known_exploited_vulnerability():
    client = KEVClient(
        http=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={
                        "vulnerabilities": [{"cveID": "CVE-2026-12345", "vendorProject": "Acme"}]
                    },
                )
            )
        )
    )

    enrichment = client.fetch("CVE-2026-12345")

    assert enrichment.kev is True


def test_reddit_client_normalizes_listing_children_without_comments():
    def handler(request):
        if request.url.path == "/api/v1/access_token":
            return httpx.Response(200, json={"access_token": "token", "token_type": "bearer"})
        assert request.headers["authorization"] == "Bearer token"
        return httpx.Response(
            200,
            json={
                "data": {
                    "children": [
                        {
                            "data": {
                                "id": "abc",
                                "subreddit": "netsec",
                                "title": "CVE-2026-12345 exploited",
                                "url": "https://example.com",
                                "created_utc": 1778655600,
                                "selftext": "Active exploitation",
                                "score": 42,
                                "num_comments": 7,
                                "upvote_ratio": 0.9,
                            }
                        }
                    ]
                }
            },
        )

    client = RedditClient(
        client_id="id",
        client_secret="secret",
        user_agent="cybertrend-test",
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    items = client.fetch_subreddit("netsec")

    assert items[0].source_type == "reddit"
    assert items[0].community == "netsec"
    assert items[0].cves == ["CVE-2026-12345"]


def test_rss_connector_normalizes_entries_from_feed_xml():
    feed = """<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Tenable</title>
      <item><title>CVE-2026-12345 advisory</title><link>https://example.com/a</link>
      <description>Patch now</description><pubDate>Wed, 13 May 2026 07:30:00 GMT</pubDate></item>
    </channel></rss>"""
    connector = RSSConnector(
        source_name="tenable",
        url="https://feeds.example/rss",
        http=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=feed))
        ),
    )

    items = connector.fetch()

    assert items[0].source_name == "tenable"
    assert items[0].cves == ["CVE-2026-12345"]


def test_rss_connector_uses_path_safe_stable_item_ids():
    feed = """<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Tenable</title>
      <item><title>Advisory</title><guid>210848 at https://www.tenable.com</guid>
      <link>https://example.com/advisory</link>
      <description>Patch now</description><pubDate>Wed, 13 May 2026 07:30:00 GMT</pubDate></item>
    </channel></rss>"""
    connector = RSSConnector(
        source_name="tenable",
        url="https://feeds.example/rss",
        http=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=feed))
        ),
    )

    items = connector.fetch()

    assert items[0].item_id.startswith("rss:tenable:")
    assert "/" not in items[0].item_id
    assert " " not in items[0].item_id


def test_rss_connector_parses_iso8601_atom_dates():
    feed = """<?xml version="1.0"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <entry><title>CVE-2026-12345 advisory</title>
      <id>tag:reddit.com,2026:/r/netsec/comments/abc/example</id>
      <link href="https://example.com/a" />
      <summary>Patch now</summary>
      <updated>2026-01-26T01:29:14+00:00</updated></entry>
    </feed>"""
    connector = RSSConnector(
        source_name="reddit_netsec",
        url="https://feeds.example/rss",
        http=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=feed))
        ),
    )

    items = connector.fetch()

    assert items[0].published_at == datetime(2026, 1, 26, 1, 29, 14, tzinfo=timezone.utc)


def test_nvd_client_parses_references_from_list():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                            "references": [
                                {"url": "https://example.com/advisory"},
                                {"url": "https://example.com/patch"},
                            ],
                        }
                    }
                ]
            },
        )

    client = NVDClient(http=httpx.Client(transport=httpx.MockTransport(handler)))
    enrichment = client.fetch("CVE-2026-12345")

    assert "https://example.com/advisory" in enrichment.references
    assert len(enrichment.references) == 2
