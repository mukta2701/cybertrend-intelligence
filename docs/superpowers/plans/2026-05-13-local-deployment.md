# Cybertrend Local Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Cybertrend run fully locally without AWS — using Docker Postgres, Gmail SMTP, OpenAI summaries, and Reddit data via public RSS feeds.

**Architecture:** Replace all AWS dependencies (SES, SQS, Lambda) with local equivalents: smtplib for email, synchronous in-process pipeline, and Reddit via public RSS feeds. Add an OpenAI GPT-4o-mini summarizer, fix five correctness bugs, and add a simple CLI runner script.

**Tech Stack:** Python 3.12, PostgreSQL 16 (Docker Compose), FastAPI, SQLAlchemy 2, Alembic, OpenAI API, Gmail SMTP (smtplib — built-in, no new dep)

---

## File Map

**Created:**
- `src/cybertrend/email/smtp.py` — Gmail SMTP sender, replaces SESEmailSender for local use
- `src/cybertrend/summaries_openai.py` — OpenAI GPT-4o-mini summarizer implementing SummaryProvider
- `run.py` — local CLI runner (`collect` / `digest` / `api` commands)
- `tests/test_smtp_email.py` — SMTP sender unit tests
- `tests/test_openai_summarizer.py` — OpenAI summarizer unit tests
- `tests/test_repository.py` — repository unit tests for new methods

**Modified:**
- `src/cybertrend/connectors/nvd.py` — fix references bug (line 41) + add `fetch_recent` for live CVE feed
- `src/cybertrend/config.py` — add smtp_host/port/user/password and email_from fields
- `src/cybertrend/db/repository.py` — add upsert_enrichment, get_enrichment, upsert_source_health, build_digest_from_items
- `src/cybertrend/services/ingestion.py` — persist enrichments, track source health, update _source_trust for RSS names
- `src/cybertrend/services/pipeline.py` — Reddit RSS feeds, wire SMTP + OpenAI, fix get_digest
- `pyproject.toml` + `requirements.txt` — add openai>=1.30
- `.env.example` — replace AWS-centric vars with SMTP and email fields
- `tests/test_pipeline.py` — update job counts to reflect RSS-only pipeline

---

### Task 1: Fix NVD references parsing bug

**Files:**
- Modify: `src/cybertrend/connectors/nvd.py:41-48`
- Modify: `tests/test_connectors.py`

- [ ] **Step 1: Write failing test**

Add to the bottom of `tests/test_connectors.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_connectors.py::test_nvd_client_parses_references_from_list -v
```

Expected: FAIL — references is empty or AttributeError

- [ ] **Step 3: Fix nvd.py**

In `src/cybertrend/connectors/nvd.py`, replace lines 41-48:

```python
        references = []
        for reference in cve_payload.get("references", {}).get("referenceData", []):
            url = reference.get("url")
            if url:
                references.append(url)
```

With:

```python
        references = []
        refs = cve_payload.get("references") or []
        if isinstance(refs, list):
            for reference in refs:
                url = reference.get("url")
                if url:
                    references.append(url)
```

- [ ] **Step 4: Run all connector tests to confirm they pass**

```bash
pytest tests/test_connectors.py -v
```

Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/connectors/nvd.py tests/test_connectors.py
git commit -m "fix: parse NVD references as list per API v2 schema"
```

---

### Task 2: Add SMTP email sender

**Files:**
- Create: `src/cybertrend/email/smtp.py`
- Modify: `src/cybertrend/config.py`
- Create: `tests/test_smtp_email.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_smtp_email.py`:

```python
from unittest.mock import MagicMock, patch

from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.models import RenderedEmail


def _message():
    return RenderedEmail(subject="Test Subject", html="<p>Test</p>", text="Test")


def test_smtp_sender_sends_to_recipients():
    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        sender = SMTPEmailSender(
            host="smtp.gmail.com",
            port=587,
            user="test@gmail.com",
            password="app-password",
            from_email="test@gmail.com",
        )
        sender.send(_message(), ["analyst@example.com"])

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("test@gmail.com", "app-password")
        mock_smtp.sendmail.assert_called_once()
        args = mock_smtp.sendmail.call_args[0]
        assert args[0] == "test@gmail.com"
        assert args[1] == ["analyst@example.com"]


def test_smtp_sender_skips_send_with_no_recipients():
    with patch("smtplib.SMTP") as mock_smtp_class:
        sender = SMTPEmailSender(
            host="smtp.gmail.com",
            port=587,
            user="test@gmail.com",
            password="app-password",
            from_email="test@gmail.com",
        )
        sender.send(_message(), [])
        mock_smtp_class.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_smtp_email.py -v
```

Expected: FAIL — `SMTPEmailSender` not found

- [ ] **Step 3: Create smtp.py**

Create `src/cybertrend/email/smtp.py`:

```python
from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable

from cybertrend.models import RenderedEmail


class SMTPEmailSender:
    def __init__(self, host: str, port: int, user: str, password: str, from_email: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_email = from_email

    def send(self, message: RenderedEmail, recipients: Iterable[str]) -> None:
        recipient_list = list(recipients)
        if not recipient_list:
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = message.subject
        msg["From"] = self.from_email
        msg["To"] = ", ".join(recipient_list)
        msg.attach(MIMEText(message.text, "plain"))
        msg.attach(MIMEText(message.html, "html"))
        with smtplib.SMTP(self.host, self.port) as smtp:
            smtp.starttls()
            smtp.login(self.user, self.password)
            smtp.sendmail(self.from_email, recipient_list, msg.as_string())
```

- [ ] **Step 4: Add SMTP fields to Settings in config.py**

In `src/cybertrend/config.py`, add these five fields to the `Settings` class after `llm_api_key`:

```python
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_smtp_email.py tests/test_config.py -v
```

Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/cybertrend/email/smtp.py src/cybertrend/config.py tests/test_smtp_email.py
git commit -m "feat: add SMTP email sender and config fields for local Gmail delivery"
```

---

### Task 3: Add OpenAI summarizer

**Files:**
- Modify: `pyproject.toml`
- Modify: `requirements.txt`
- Create: `src/cybertrend/summaries_openai.py`
- Create: `tests/test_openai_summarizer.py`

- [ ] **Step 1: Add openai dependency**

In `pyproject.toml`, add to the `dependencies` list (after `structlog` line):

```toml
  "openai>=1.30",
```

In `requirements.txt`, add:

```
openai>=1.30
```

- [ ] **Step 2: Install the new dependency**

```bash
pip install -e ".[dev,infra]"
```

Expected: `Successfully installed openai-...`

- [ ] **Step 3: Write failing tests**

Create `tests/test_openai_summarizer.py`:

```python
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from cybertrend.models import EngagementMetrics, SourceType, TrendItem
from cybertrend.summaries_openai import OpenAISummaryProvider


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

        provider = OpenAISummaryProvider(api_key="sk-test")
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

        provider = OpenAISummaryProvider(api_key="sk-test")
        item = _item()
        result = provider.summarize(item, enrichments={})

    assert result.summary == item.summary
    assert result.item_id == item.item_id
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
pytest tests/test_openai_summarizer.py -v
```

Expected: FAIL — module not found

- [ ] **Step 5: Create summaries_openai.py**

Create `src/cybertrend/summaries_openai.py`:

```python
from __future__ import annotations

import json
from typing import Mapping

from openai import OpenAI

from cybertrend.models import CVEEnrichment, TrendItem


class OpenAISummaryProvider:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def summarize(self, item: TrendItem, enrichments: Mapping[str, CVEEnrichment]) -> TrendItem:
        cve_context = ", ".join(item.cves) or "no specific CVEs"
        prompt = (
            "You are a cybersecurity analyst. Summarize this threat intelligence item.\n\n"
            f"Title: {item.title}\n"
            f"CVEs: {cve_context}\n"
            f"Current summary: {item.summary or 'none'}\n"
            f"Severity: {item.severity_label}\n\n"
            "Return JSON with exactly these keys:\n"
            "- summary: 1-2 sentences on what happened (max 300 characters)\n"
            "- what_went_wrong: the vulnerability or issue (max 300 characters)\n"
            "- why_this_matters_now: why defenders should act now (max 300 characters)"
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=400,
        )
        data = json.loads(response.choices[0].message.content)
        summary = str(data.get("summary") or "").strip()
        what_went_wrong = str(data.get("what_went_wrong") or "").strip()
        why_now = str(data.get("why_this_matters_now") or "").strip()
        if not summary or not what_went_wrong:
            return item
        return item.model_copy(
            update={
                "summary": summary[:800],
                "what_went_wrong": what_went_wrong[:800],
                "why_this_matters_now": why_now[:800],
            }
        )
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
pytest tests/test_openai_summarizer.py -v
```

Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/summaries_openai.py tests/test_openai_summarizer.py pyproject.toml requirements.txt
git commit -m "feat: add OpenAI GPT-4o-mini summarizer for CVE-bearing items"
```

---

### Task 4: Switch Reddit from OAuth to public RSS feeds

**Files:**
- Modify: `src/cybertrend/services/pipeline.py`
- Modify: `src/cybertrend/services/ingestion.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Update test_pipeline.py to reflect RSS-only jobs**

In `tests/test_pipeline.py`, replace the entire file:

```python
from cybertrend.services.pipeline import PipelineService


class FakeIngestionService:
    def __init__(self):
        self.jobs = []

    def process_job(self, job):
        self.jobs.append(job)
        return 2


def test_manual_run_processes_all_rss_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 6
    assert result["processed_jobs"] == 6
    assert result["stored_items"] == 12
    assert len(result["failed_jobs"]) == 0
    source_types = {job["source_type"] for job in ingestion.jobs}
    assert source_types == {"rss"}
```

- [ ] **Step 2: Run test to confirm it fails (pipeline still uses old logic)**

```bash
pytest tests/test_pipeline.py -v
```

Expected: FAIL — stored_items mismatch

- [ ] **Step 3: Replace constants and remove Reddit OAuth in pipeline.py**

In `src/cybertrend/services/pipeline.py`, remove this import:

```python
from cybertrend.connectors.reddit import RedditClient
```

Replace the two top-level constants:

```python
DEFAULT_REDDIT_COMMUNITIES = ["netsec", "cybersecurity", "threatintel", "blueteamsec", "Malware"]
DEFAULT_RSS_FEEDS = {
    "tenable": "https://www.tenable.com/security/research/feed",
}
```

With:

```python
DEFAULT_RSS_FEEDS = {
    "reddit_netsec": "https://www.reddit.com/r/netsec/.rss",
    "reddit_cybersecurity": "https://www.reddit.com/r/cybersecurity/.rss",
    "reddit_threatintel": "https://www.reddit.com/r/threatintel/.rss",
    "reddit_blueteamsec": "https://www.reddit.com/r/blueteamsec/.rss",
    "reddit_malware": "https://www.reddit.com/r/Malware/.rss",
    "tenable": "https://www.tenable.com/security/research/feed",
}
```

- [ ] **Step 4: Replace trigger_manual_run job-building loop**

In `pipeline.py`'s `trigger_manual_run`, remove:

```python
        for community in DEFAULT_REDDIT_COMMUNITIES:
            jobs.append(
                {
                    "source_type": "reddit",
                    "source_name": "reddit",
                    "community": community,
                    "requested_at": requested_at,
                }
            )
        for name, url in DEFAULT_RSS_FEEDS.items():
            jobs.append(
                {
                    "source_type": "rss",
                    "source_name": name,
                    "url": url,
                    "requested_at": requested_at,
                }
            )
```

Replace with:

```python
        for name, url in DEFAULT_RSS_FEEDS.items():
            jobs.append(
                {
                    "source_type": "rss",
                    "source_name": name,
                    "url": url,
                    "requested_at": requested_at,
                }
            )
```

- [ ] **Step 5: Update _source_trust in ingestion.py for RSS source names**

In `src/cybertrend/services/ingestion.py`, replace `_source_trust`:

```python
    def _source_trust(self, item: TrendItem) -> float:
        if item.source_name in {"reddit_netsec", "reddit_blueteamsec"}:
            return 0.85
        if item.source_name in {"tenable", "nvd", "kev"}:
            return 0.95
        return 0.70
```

- [ ] **Step 6: Run all tests to confirm they pass**

```bash
pytest tests/test_pipeline.py tests/test_connectors.py -v
```

Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/services/pipeline.py src/cybertrend/services/ingestion.py tests/test_pipeline.py
git commit -m "feat: replace Reddit OAuth with public RSS feeds, no credentials required"
```

---

### Task 5: Persist CVE enrichments with 24-hour cache

**Files:**
- Modify: `src/cybertrend/db/repository.py`
- Modify: `src/cybertrend/services/ingestion.py`
- Create: `tests/test_repository.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_repository.py`:

```python
from datetime import datetime, timezone
from unittest.mock import MagicMock

from cybertrend.db.repository import Repository
from cybertrend.models import CVEEnrichment


def _session():
    return MagicMock()


def test_upsert_enrichment_calls_execute_and_commit():
    session = _session()
    repo = Repository(session)
    enrichment = CVEEnrichment(cve="CVE-2026-12345", cvss_base=9.8, kev=True)

    repo.upsert_enrichment(enrichment)

    session.execute.assert_called_once()
    session.commit.assert_called_once()


def test_get_enrichment_returns_none_when_record_missing():
    session = _session()
    session.get.return_value = None
    repo = Repository(session)

    result = repo.get_enrichment("CVE-2026-12345")

    assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_repository.py -v
```

Expected: FAIL — `upsert_enrichment` not found

- [ ] **Step 3: Add CVEEnrichmentRecord to repository.py imports**

In `src/cybertrend/db/repository.py`, replace the existing models import:

```python
from cybertrend.db.models import (
    AlertDeliveryRecord,
    DigestRunRecord,
    SourceHealthRecord,
    SourcePolicyRecord,
    TrendItemRecord,
)
```

With:

```python
from cybertrend.db.models import (
    AlertDeliveryRecord,
    CVEEnrichmentRecord,
    DigestRunRecord,
    SourceHealthRecord,
    SourcePolicyRecord,
    TrendItemRecord,
)
```

Also ensure `timedelta` is in the datetime import at the top:

```python
from datetime import date, datetime, timedelta, timezone
```

- [ ] **Step 4: Add get_enrichment and upsert_enrichment to Repository**

Add these two methods to the `Repository` class in `repository.py`:

```python
    def get_enrichment(self, cve: str) -> Optional[CVEEnrichment]:
        record = self.session.get(CVEEnrichmentRecord, cve)
        if record is None:
            return None
        updated = record.updated_at
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - updated > timedelta(hours=24):
            return None
        return CVEEnrichment(
            cve=record.cve,
            cvss_base=record.cvss_base,
            cvss_severity=record.cvss_severity,
            epss_probability=record.epss_probability,
            epss_percentile=record.epss_percentile,
            kev=record.kev,
            tenable_vpr=record.tenable_vpr,
            exploit_maturity=record.exploit_maturity,
            vendor_project=record.vendor_project,
            product=record.product,
            vulnerability_name=record.vulnerability_name,
            required_action=record.required_action,
            references=list(record.references or []),
            raw=dict(record.raw or {}),
        )

    def upsert_enrichment(self, enrichment: CVEEnrichment) -> None:
        values = {
            "cve": enrichment.cve,
            "cvss_base": enrichment.cvss_base,
            "cvss_severity": enrichment.cvss_severity,
            "epss_probability": enrichment.epss_probability,
            "epss_percentile": enrichment.epss_percentile,
            "kev": enrichment.kev,
            "tenable_vpr": enrichment.tenable_vpr,
            "exploit_maturity": enrichment.exploit_maturity,
            "vendor_project": enrichment.vendor_project,
            "product": enrichment.product,
            "vulnerability_name": enrichment.vulnerability_name,
            "required_action": enrichment.required_action,
            "references": enrichment.references,
            "raw": enrichment.raw,
        }
        stmt = insert(CVEEnrichmentRecord).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CVEEnrichmentRecord.cve],
            set_={k: v for k, v in values.items() if k != "cve"},
        )
        self.session.execute(stmt)
        self.session.commit()
```

- [ ] **Step 5: Update _enrich_item in ingestion.py to check cache and persist**

In `src/cybertrend/services/ingestion.py`, replace `_enrich_item`:

```python
    def _enrich_item(self, item: TrendItem) -> Dict[str, CVEEnrichment]:
        results: Dict[str, CVEEnrichment] = {}
        for cve in item.cves:
            cached = (
                self.repository.get_enrichment(cve)
                if getattr(self.repository, "get_enrichment", None)
                else None
            )
            if cached:
                results[cve] = cached
                continue
            pieces = []
            for client in (self.nvd_client, self.epss_client, self.kev_client, self.tenable_client):
                try:
                    pieces.append(client.fetch(cve))
                except Exception:
                    continue
            merged = merge_enrichments(cve, pieces)
            results[cve] = merged
            if getattr(self.repository, "upsert_enrichment", None):
                try:
                    self.repository.upsert_enrichment(merged)
                except Exception:
                    pass
        return results
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
pytest tests/test_repository.py -v
```

Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/db/repository.py src/cybertrend/services/ingestion.py tests/test_repository.py
git commit -m "feat: cache CVE enrichments in DB to avoid redundant external API calls"
```

---

### Task 6: Track source health on ingestion

**Files:**
- Modify: `src/cybertrend/db/repository.py`
- Modify: `src/cybertrend/services/ingestion.py`
- Modify: `tests/test_repository.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_repository.py`:

```python
def test_upsert_source_health_creates_record_on_success():
    session = _session()
    session.get.return_value = None
    repo = Repository(session)

    repo.upsert_source_health("reddit_netsec", "rss", success=True)

    session.add.assert_called_once()
    session.commit.assert_called_once()
    record = session.add.call_args[0][0]
    assert record.source_name == "reddit_netsec"
    assert record.consecutive_failures == 0
    assert record.last_success_at is not None


def test_upsert_source_health_increments_failure_count_on_existing_record():
    session = _session()
    existing = MagicMock()
    existing.consecutive_failures = 2
    session.get.return_value = existing
    repo = Repository(session)

    repo.upsert_source_health("reddit_netsec", "rss", success=False, error="timeout")

    assert existing.consecutive_failures == 3
    assert existing.last_error == "timeout"
    session.commit.assert_called_once()
```

Also add `from unittest.mock import MagicMock` at the top of `tests/test_repository.py` if not already there.

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_repository.py -v
```

Expected: FAIL — `upsert_source_health` not found

- [ ] **Step 3: Add upsert_source_health to Repository**

Add to the `Repository` class in `repository.py`:

```python
    def upsert_source_health(
        self,
        source_name: str,
        source_type: str,
        *,
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        existing = self.session.get(SourceHealthRecord, source_name)
        if existing:
            if success:
                existing.last_success_at = now
                existing.consecutive_failures = 0
                existing.last_error = None
            else:
                existing.last_error_at = now
                existing.last_error = error
                existing.consecutive_failures = (existing.consecutive_failures or 0) + 1
        else:
            record = SourceHealthRecord(
                source_name=source_name,
                source_type=source_type,
                last_success_at=now if success else None,
                last_error_at=None if success else now,
                last_error=None if success else error,
                consecutive_failures=0 if success else 1,
            )
            self.session.add(record)
        self.session.commit()
```

- [ ] **Step 4: Update process_job in ingestion.py to call upsert_source_health**

In `src/cybertrend/services/ingestion.py`, replace `process_job`:

```python
    def process_job(self, job: dict) -> int:
        source_type = job.get("source_type", "unknown")
        source_name = job.get("source_name", "unknown")
        items: List[TrendItem] = []
        try:
            if source_type == "reddit":
                if not self.reddit_client:
                    raise RuntimeError("Reddit client is not configured")
                items = self.reddit_client.fetch_subreddit(job["community"])
            elif source_type == "rss":
                items = RSSConnector(source_name=source_name, url=job["url"]).fetch()
            else:
                raise ValueError(f"Unsupported source_type: {source_type}")
            count = self.process_items(items)
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(source_name, source_type, success=True)
            return count
        except Exception as exc:
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(
                    source_name, source_type, success=False, error=str(exc)
                )
            raise
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
pytest tests/test_repository.py -v
```

Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/cybertrend/db/repository.py src/cybertrend/services/ingestion.py tests/test_repository.py
git commit -m "feat: record source health on every ingestion success and failure"
```

---

### Task 7: Build daily digest from stored trend items

**Files:**
- Modify: `src/cybertrend/db/repository.py`
- Modify: `src/cybertrend/services/pipeline.py`
- Modify: `tests/test_repository.py`

- [ ] **Step 1: Write failing test for digest builder**

Add to `tests/test_repository.py`:

```python
from datetime import date


def test_build_digest_from_items_groups_by_severity():
    from cybertrend.db.models import TrendItemRecord
    from cybertrend.models import DigestPayload

    record = MagicMock(spec=TrendItemRecord)
    record.item_id = "item-1"
    record.source_type = "rss"
    record.source_name = "reddit_netsec"
    record.community = "netsec"
    record.title = "Critical bug"
    record.url = "https://example.com"
    record.published_at = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    record.summary = "summary"
    record.what_went_wrong = ""
    record.why_this_matters_now = ""
    record.cves = ["CVE-2026-12345"]
    record.cvss_base = 9.8
    record.epss_probability = None
    record.epss_percentile = None
    record.kev_flag = True
    record.tenable_vpr = None
    record.exploit_evidence = None
    record.engagement_metrics = {}
    record.criticality_score = 91.0
    record.confidence_score = 80.0
    record.severity_label = "Critical"
    record.score_breakdown = {}
    record.raw = {}

    session = _session()
    session.scalars.return_value = [record]
    repo = Repository(session)

    payload = repo.build_digest_from_items(date(2026, 5, 13))

    assert isinstance(payload, DigestPayload)
    critical_section = next(s for s in payload.sections if s.severity == "Critical")
    assert len(critical_section.items) == 1
    assert critical_section.items[0].item_id == "item-1"
```

Also add `from datetime import date, datetime, timezone` at the top of the test file.

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_repository.py::test_build_digest_from_items_groups_by_severity -v
```

Expected: FAIL — `build_digest_from_items` not found

- [ ] **Step 3: Add DigestSection to repository.py imports**

In `repository.py`, update the models import:

```python
from cybertrend.models import (
    CVEEnrichment,
    DigestPayload,
    DigestSection,
    SourceHealth,
    SourcePolicy,
    SourceType,
    TrendItem,
)
```

- [ ] **Step 4: Add build_digest_from_items to Repository**

Add to the `Repository` class:

```python
    def build_digest_from_items(self, digest_date: date) -> DigestPayload:
        start = datetime(
            digest_date.year, digest_date.month, digest_date.day, tzinfo=timezone.utc
        )
        end = start + timedelta(days=1)
        records = list(
            self.session.scalars(
                select(TrendItemRecord)
                .where(TrendItemRecord.published_at >= start)
                .where(TrendItemRecord.published_at < end)
                .order_by(TrendItemRecord.criticality_score.desc())
            )
        )
        buckets: Dict[str, List[TrendItem]] = {"Critical": [], "High": [], "Medium": []}
        for record in records:
            item = _record_to_item(record)
            if item.severity_label in buckets:
                buckets[item.severity_label].append(item)
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(
                    name="Critical - Act Now", severity="Critical", items=buckets["Critical"]
                ),
                DigestSection(
                    name="High - Prioritize This Week", severity="High", items=buckets["High"]
                ),
                DigestSection(
                    name="Medium - Track", severity="Medium", items=buckets["Medium"]
                ),
            ],
        )
```

- [ ] **Step 5: Update get_digest in pipeline.py to use the builder**

In `src/cybertrend/services/pipeline.py`, replace `get_digest`:

```python
    def get_digest(self, digest_date: date) -> DigestPayload:
        if self.repository:
            stored = self.repository.get_digest(digest_date)
            if stored:
                return stored
            if getattr(self.repository, "build_digest_from_items", None):
                return self.repository.build_digest_from_items(digest_date)
        return DigestPayload(
            digest_date=digest_date,
            sections=[
                DigestSection(name="Critical - Act Now", severity="Critical", items=[]),
                DigestSection(name="High - Prioritize This Week", severity="High", items=[]),
                DigestSection(name="Medium - Track", severity="Medium", items=[]),
            ],
        )
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
pytest tests/test_repository.py -v
```

Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/db/repository.py src/cybertrend/services/pipeline.py tests/test_repository.py
git commit -m "feat: build daily digest from stored trend items grouped by severity"
```

---

### Task 8: Wire SMTP + OpenAI into pipeline, add local runner, update .env.example

**Files:**
- Modify: `src/cybertrend/services/pipeline.py`
- Create: `run.py`
- Modify: `.env.example`

- [ ] **Step 1: Update pipeline.py from_settings**

In `src/cybertrend/services/pipeline.py`, add imports at the top:

```python
from cybertrend.email.smtp import SMTPEmailSender
from cybertrend.summaries import HybridSummaryProvider
```

Remove:
```python
from cybertrend.connectors.reddit import RedditClient
from cybertrend.email.ses import SESEmailSender
```

Replace the entire `from_settings` method body with:

```python
    @classmethod
    def from_settings(cls, settings: Settings) -> "PipelineService":
        session_factory = make_session_factory(settings.database_url)
        repository = Repository(scoped_session(session_factory))
        source_queue = (
            SQSQueue(os.environ["SOURCE_QUEUE_URL"], region_name=settings.aws_region)
            if os.environ.get("SOURCE_QUEUE_URL")
            else None
        )
        alert_queue = (
            SQSQueue(os.environ["ALERT_QUEUE_URL"], region_name=settings.aws_region)
            if os.environ.get("ALERT_QUEUE_URL")
            else None
        )
        email_sender = None
        if settings.smtp_user and settings.smtp_password:
            email_sender = SMTPEmailSender(
                host=settings.smtp_host,
                port=settings.smtp_port,
                user=settings.smtp_user,
                password=settings.smtp_password,
                from_email=settings.email_from or settings.smtp_user,
            )
        llm_provider = None
        if settings.llm_provider == "openai" and settings.llm_api_key:
            from cybertrend.summaries_openai import OpenAISummaryProvider
            llm_provider = OpenAISummaryProvider(api_key=settings.llm_api_key)
        summarizer = HybridSummaryProvider(llm_provider=llm_provider)
        ingestion = IngestionService(
            repository=repository,
            alert_queue=alert_queue,
            tenable_client=TenableVPRClient(
                access_key=settings.tenable_access_key,
                secret_key=settings.tenable_secret_key,
            ),
            summarizer=summarizer,
        )
        return cls(
            repository=repository,
            queue=source_queue,
            alert_queue=alert_queue,
            email_sender=email_sender,
            ingestion_service=ingestion,
            settings=settings,
        )
```

- [ ] **Step 2: Run full test suite to confirm nothing broke**

```bash
pytest -v
```

Expected: All PASS

- [ ] **Step 3: Create run.py**

Create `run.py` at the project root:

```python
#!/usr/bin/env python3
"""Local CLI runner for Cybertrend."""
from __future__ import annotations

import sys
from datetime import datetime, timezone


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        print("Usage: python run.py [collect|digest|api]")
        print()
        print("  collect   Fetch all RSS feeds and store scored items")
        print("  digest    Build and email today's digest")
        print("  api       Start the local API on http://127.0.0.1:8000")
        sys.exit(0)

    command = sys.argv[1]

    from cybertrend.config import get_settings
    from cybertrend.services.pipeline import PipelineService

    settings = get_settings()
    pipeline = PipelineService.from_settings(settings)

    if command == "collect":
        result = pipeline.trigger_manual_run()
        print(f"Run ID:       {result['run_id']}")
        print(f"Jobs done:    {result['processed_jobs']} / {result['queued_jobs']}")
        print(f"Items stored: {result['stored_items']}")
        if result["failed_jobs"]:
            print(f"Failures:     {result['failed_jobs']}")

    elif command == "digest":
        today = datetime.now(timezone.utc).date()
        result = pipeline.send_daily_digest(today)
        print(f"Digest {result['digest_date']} — sent: {result['sent']}")

    elif command == "api":
        import uvicorn
        from cybertrend.api import create_app
        app = create_app(pipeline=pipeline, api_key=settings.api_key)
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)

    else:
        print(f"Unknown command: {command!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Update .env.example**

Replace the entire contents of `.env.example`:

```
APP_ENV=local
DATABASE_URL=postgresql+psycopg://cybertrend:cybertrend@localhost:5432/cybertrend
API_KEY=replace-me

# Gmail SMTP — create an App Password at myaccount.google.com → Security → App Passwords
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASSWORD=your-16-char-app-password
EMAIL_FROM=youremail@gmail.com
ALERT_RECIPIENTS=youremail@gmail.com
DIGEST_RECIPIENTS=youremail@gmail.com

# OpenAI summarizer
LLM_PROVIDER=openai
LLM_API_KEY=sk-...

# Optional: NVD enrichment (free key at nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=

# Optional: Tenable VPR enrichment (requires Tenable.io subscription)
TENABLE_ACCESS_KEY=
TENABLE_SECRET_KEY=
```

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/services/pipeline.py run.py .env.example
git commit -m "feat: wire SMTP and OpenAI into pipeline, add local run.py CLI"
```

---

### Task 9: Add NVD as a live CVE feed source

**Files:**
- Modify: `src/cybertrend/connectors/nvd.py` — add `fetch_recent` method
- Modify: `src/cybertrend/services/ingestion.py` — handle `source_type="nvd"` in `process_job`
- Modify: `src/cybertrend/services/pipeline.py` — add NVD job to collect cycle and update job count
- Modify: `tests/test_connectors.py` — add test for `fetch_recent`
- Modify: `tests/test_pipeline.py` — update job count from 6 to 7

- [ ] **Step 1: Write failing test for NVD fetch_recent**

Add to the bottom of `tests/test_connectors.py`:

```python
def test_nvd_client_fetches_recent_cves_as_trend_items():
    def handler(request):
        assert "pubStartDate" in str(request.url)
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 1,
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-99999",
                            "published": "2026-05-13T08:00:00.000",
                            "descriptions": [
                                {"lang": "en", "value": "A critical buffer overflow in Example Corp firmware."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                            "references": [{"url": "https://example.com/advisory"}],
                        }
                    }
                ],
            },
        )

    client = NVDClient(http=httpx.Client(transport=httpx.MockTransport(handler)))
    items = client.fetch_recent(hours_back=24)

    assert len(items) == 1
    assert items[0].item_id == "nvd:CVE-2026-99999"
    assert items[0].source_type.value == "nvd"
    assert items[0].cves == ["CVE-2026-99999"]
    assert items[0].cvss_base == 9.1
    assert "buffer overflow" in items[0].summary.lower()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_connectors.py::test_nvd_client_fetches_recent_cves_as_trend_items -v
```

Expected: FAIL — `fetch_recent` not found

- [ ] **Step 3: Add fetch_recent to NVDClient**

In `src/cybertrend/connectors/nvd.py`, add these imports at the top:

```python
from datetime import datetime, timedelta, timezone
from typing import List

from cybertrend.models import CVEEnrichment, SourceType, TrendItem
from cybertrend.text import collapse_whitespace
```

Then add the `fetch_recent` method to `NVDClient`:

```python
    def fetch_recent(self, hours_back: int = 24) -> List[TrendItem]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        response = self.http.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        items: List[TrendItem] = []
        for vuln in data.get("vulnerabilities") or []:
            cve_payload = vuln.get("cve", {})
            cve_id = cve_payload.get("id", "")
            if not cve_id:
                continue
            description = ""
            for desc in cve_payload.get("descriptions") or []:
                if desc.get("lang") == "en":
                    description = collapse_whitespace(desc.get("value") or "")
                    break
            metrics = cve_payload.get("metrics", {})
            cvss_base = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []
                if entries:
                    cvss_base = entries[0].get("cvssData", {}).get("baseScore")
                    break
            published_str = cve_payload.get("published") or ""
            try:
                published_at = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00").split(".")[0]
                ).replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                published_at = now
            items.append(
                TrendItem(
                    item_id=f"nvd:{cve_id}",
                    source_type=SourceType.NVD,
                    source_name="nvd",
                    title=f"{cve_id} — {description[:120]}" if description else cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=published_at,
                    summary=description,
                    cves=[cve_id],
                    cvss_base=cvss_base,
                    raw=cve_payload,
                )
            )
        return items
```

- [ ] **Step 4: Run connector tests to confirm they pass**

```bash
pytest tests/test_connectors.py -v
```

Expected: All PASS

- [ ] **Step 5: Update ingestion.py to handle source_type="nvd"**

In `src/cybertrend/services/ingestion.py`, add import at top:

```python
from cybertrend.connectors.nvd import NVDClient
```

In `process_job`, add an `elif` branch for NVD after the `rss` branch:

```python
    def process_job(self, job: dict) -> int:
        source_type = job.get("source_type", "unknown")
        source_name = job.get("source_name", "unknown")
        items: List[TrendItem] = []
        try:
            if source_type == "reddit":
                if not self.reddit_client:
                    raise RuntimeError("Reddit client is not configured")
                items = self.reddit_client.fetch_subreddit(job["community"])
            elif source_type == "rss":
                items = RSSConnector(source_name=source_name, url=job["url"]).fetch()
            elif source_type == "nvd":
                hours_back = int(job.get("hours_back", 24))
                items = self.nvd_client.fetch_recent(hours_back=hours_back)
            else:
                raise ValueError(f"Unsupported source_type: {source_type}")
            count = self.process_items(items)
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(source_name, source_type, success=True)
            return count
        except Exception as exc:
            if getattr(self.repository, "upsert_source_health", None):
                self.repository.upsert_source_health(
                    source_name, source_type, success=False, error=str(exc)
                )
            raise
```

- [ ] **Step 6: Add NVD job to pipeline.py collect cycle**

In `src/cybertrend/services/pipeline.py`, add a new constant below `DEFAULT_RSS_FEEDS`:

```python
DEFAULT_NVD_JOBS = [
    {"source_type": "nvd", "source_name": "nvd", "hours_back": 24},
]
```

In `trigger_manual_run`, add the NVD jobs after the RSS loop:

```python
        for name, url in DEFAULT_RSS_FEEDS.items():
            jobs.append(
                {
                    "source_type": "rss",
                    "source_name": name,
                    "url": url,
                    "requested_at": requested_at,
                }
            )
        for nvd_job in DEFAULT_NVD_JOBS:
            jobs.append({**nvd_job, "requested_at": requested_at})
```

- [ ] **Step 7: Update test_pipeline.py for the new job count**

In `tests/test_pipeline.py`, update the assertions (6 RSS + 1 NVD = 7 jobs, 7 × 2 = 14 items):

```python
def test_manual_run_processes_all_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 7
    assert result["processed_jobs"] == 7
    assert result["stored_items"] == 14
    assert len(result["failed_jobs"]) == 0
    source_types = {job["source_type"] for job in ingestion.jobs}
    assert source_types == {"rss", "nvd"}
```

- [ ] **Step 8: Update _source_trust in ingestion.py for nvd source**

In `src/cybertrend/services/ingestion.py`, the `_source_trust` method already gives `"nvd"` a score of `0.95`. No change needed — confirm it reads:

```python
    def _source_trust(self, item: TrendItem) -> float:
        if item.source_name in {"reddit_netsec", "reddit_blueteamsec"}:
            return 0.85
        if item.source_name in {"tenable", "nvd", "kev"}:
            return 0.95
        return 0.70
```

- [ ] **Step 9: Run full test suite**

```bash
pytest -v
```

Expected: All PASS

- [ ] **Step 10: Commit**

```bash
git add src/cybertrend/connectors/nvd.py src/cybertrend/services/ingestion.py \
        src/cybertrend/services/pipeline.py tests/test_connectors.py tests/test_pipeline.py
git commit -m "feat: add NVD as live CVE feed source, fetching newly published CVEs on each collect run"
```

---

### Task 10: First local run — verify end to end

- [ ] **Step 1: Copy .env and fill in credentials**

```bash
cp .env.example .env
```

Open `.env` and set:
- `API_KEY` → any string you choose, e.g. `mukta-cybertrend-2026`
- `SMTP_USER` → your Gmail address
- `SMTP_PASSWORD` → your 16-character Gmail App Password
- `EMAIL_FROM` → same as `SMTP_USER`
- `ALERT_RECIPIENTS` → your Gmail address
- `DIGEST_RECIPIENTS` → your Gmail address
- `LLM_API_KEY` → your OpenAI key starting with `sk-`

- [ ] **Step 2: Start Postgres**

```bash
docker compose up -d postgres
```

```bash
docker compose ps
```

Expected: status shows `healthy`

- [ ] **Step 3: Apply database migrations**

```bash
alembic upgrade head
```

Expected output ends with: `Running upgrade  -> 20260513_0001, Initial production schema`

- [ ] **Step 4: Run the full test suite**

```bash
pytest --cov=cybertrend --cov-report=term-missing
```

Expected: All PASS, no import errors

- [ ] **Step 5: Run a collection cycle**

```bash
python run.py collect
```

Expected output:
```
Run ID:       manual-<uuid>
Jobs done:    7 / 7
Items stored: <some number>
```

- [ ] **Step 6: Browse items via the API**

In one terminal:
```bash
python run.py api
```

In another terminal:
```bash
curl -s -H "x-api-key: mukta-cybertrend-2026" http://127.0.0.1:8000/items | python3 -m json.tool | head -60
```

Expected: JSON with `items` array containing scored cybersecurity posts

- [ ] **Step 7: Send a test digest email**

```bash
python run.py digest
```

Expected: `Digest 2026-05-13 — sent: True` and the email arrives in your Gmail inbox
