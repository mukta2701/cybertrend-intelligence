from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from cybertrend.models import EngagementMetrics, SourceType, TrendItem
from cybertrend.summaries_openai import OpenAISummaryProvider

OPENAI_KEY_PLACEHOLDER = "placeholder"


def _item():
    return TrendItem(
        item_id="item-1",
        source_type=SourceType.RSS,
        source_name="thehackernews",
        title="Cisco ASA Auth Bypass Exploited in the Wild",
        url="https://example.com",
        published_at=datetime(2026, 5, 13, 7, 30, tzinfo=timezone.utc),
        cves=["CVE-2026-12345"],
        cvss_base=9.8,
        kev_flag=True,
        severity_label="Critical",
        engagement_metrics=EngagementMetrics(),
    )


def test_openai_summarizer_configures_bounded_client_timeout():
    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)

    mock_openai_class.assert_called_once_with(
        api_key=OPENAI_KEY_PLACEHOLDER,
        timeout=10.0,
        max_retries=0,
    )


def test_openai_summarizer_populates_llm_analysis():
    mock_response = MagicMock()
    mock_response.choices[0].message.content = """{
        "headline": "Cisco ASA — Auth bypass enables unauthenticated remote access",
        "affected_assets": "Cisco ASA and FTD appliances running firmware < 9.18.4",
        "vulnerability": "CVE-2026-12345 is an authentication bypass in the Cisco ASA VPN component that allows unauthenticated access to protected management functions.",
        "threat": "An unauthenticated remote attacker can reach protected administrative functions and potentially execute commands or take over the device.",
        "exploitation_status": "Actively exploited — CISA KEV listed and observed in ransomware campaigns.",
        "organizational_risk": "Unpatched internet-facing firewalls can give attackers initial network access, enabling lateral movement and ransomware deployment.",
        "recommended_action": "Patch to version 9.18.4 or later immediately; restrict management interface exposure to trusted IPs.",
        "why_it_matters": "Edge firewall compromise provides attackers a persistent foothold with full network visibility."
    }"""

    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)
        result = provider.summarize(_item(), enrichments={})

    assert result.llm_analysis is not None
    assert "Cisco" in result.llm_analysis["headline"]
    assert "CVE-2026-12345" in result.llm_analysis["vulnerability"]
    assert "unauthenticated" in result.llm_analysis["threat"].lower()
    assert "ransomware" in result.llm_analysis["organizational_risk"].lower()
    assert result.llm_analysis["recommended_action"] != ""
    assert result.llm_analysis["why_it_matters"] != ""
    # Legacy fields also populated
    assert result.summary == result.llm_analysis["vulnerability"]
    assert result.what_went_wrong == result.llm_analysis["threat"]


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

    assert result.llm_analysis is None
    assert result.item_id == item.item_id


def test_openai_summarizer_includes_action_fields_in_llm_analysis():
    mock_response = MagicMock()
    mock_response.choices[0].message.content = """{
        "headline": "Cisco ASA — Auth bypass enables unauthenticated remote access",
        "affected_assets": "Cisco ASA and FTD appliances",
        "vulnerability": "CVE-2026-12345 is an auth bypass.",
        "threat": "Unauthenticated remote access.",
        "exploitation_status": "Actively exploited",
        "organizational_risk": "Edge firewall compromise.",
        "recommended_action": "Patch to 9.18.4 immediately.",
        "why_it_matters": "Active ransomware campaigns.",
        "action_type": "Patch",
        "action_owner": "Network team",
        "timeframe": "Now"
    }"""

    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)
        result = provider.summarize(_item(), enrichments={})

    assert result.llm_analysis["action_type"] == "Patch"
    assert result.llm_analysis["action_owner"] == "Network team"
    assert result.llm_analysis["timeframe"] == "Now"


def test_openai_summarizer_uses_safe_fallbacks_for_missing_action_fields():
    mock_response = MagicMock()
    mock_response.choices[0].message.content = """{
        "headline": "Cisco ASA — Auth bypass enables unauthenticated remote access",
        "affected_assets": "Cisco ASA and FTD appliances",
        "vulnerability": "CVE-2026-12345 is an auth bypass.",
        "threat": "Unauthenticated remote access.",
        "exploitation_status": "Actively exploited",
        "organizational_risk": "Edge firewall compromise.",
        "recommended_action": "Patch to 9.18.4 immediately.",
        "why_it_matters": "Active ransomware campaigns."
    }"""

    with patch("cybertrend.summaries_openai.OpenAI") as mock_openai_class:
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAISummaryProvider(api_key=OPENAI_KEY_PLACEHOLDER)
        result = provider.summarize(_item(), enrichments={})

    assert result.llm_analysis["action_type"] == "Investigate"
    assert result.llm_analysis["action_owner"] == "SOC"
    assert result.llm_analysis["timeframe"] == "This week"
