from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from cybertrend.models import EngagementMetrics, SourceType, TrendItem
from cybertrend.summaries_openai import OpenAISummaryProvider

OPENAI_KEY_PLACEHOLDER = "placeholder"


def _item():
    return TrendItem(
        item_id="item-1",
        source_type=SourceType.RSS,
        source_name="reddit_netsec",
        title="CVE-2026-12345 remote code execution exploited",
        url="https://example.com",
        published_at=datetime(2026, 5, 13, 7, 30, tzinfo=timezone.utc),
        cves=["CVE-2026-12345"],
        cvss_base=9.8,
        kev_flag=True,
        severity_label="Critical",
        engagement_metrics=EngagementMetrics(),
    )


def test_openai_summarizer_enriches_summary_fields():
    mock_response = MagicMock()
    mock_response.choices[0].message.content = (
        '{"summary": "Critical RCE bug actively exploited.", '
        '"what_went_wrong": "Unauthenticated remote code execution in edge devices.", '
        '"why_this_matters_now": "CISA KEV confirms in-the-wild exploitation."}'
    )

    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)
        result = provider.summarize(_item(), enrichments={})

    assert result.summary == "Critical RCE bug actively exploited."
    assert "unauthenticated" in result.what_went_wrong.lower()
    assert "KEV" in result.why_this_matters_now


def test_openai_summarizer_falls_back_when_response_is_empty():
    mock_response = MagicMock()
    mock_response.choices[0].message.content = "{}"

    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)
        item = _item()
        result = provider.summarize(item, enrichments={})

    assert result.summary == item.summary
    assert result.item_id == item.item_id
