# Operational Fixes + Phase 2 Action Fields

**Date:** 2026-06-02

## Summary

Four scoped changes that take the pipeline from broken-scheduler to fully operational, and advance the digest to Phase 2 of the gap-analysis roadmap.

1. Fix the launchd scheduler so it auto-starts Docker and fires at 8 AM.
2. Fix three reliability bugs in the pipeline: inaccurate `sent` flag, digest never saved to `digest_runs`, Critical items never receiving SMTP alerts.
3. Add Phase 2 structured action fields (`action_type`, `action_owner`, `timeframe`) to LLM output.
4. Render the new action fields as a compact badge row at the top of each digest card.

---

## Section 1 — Scheduler

### Problem

The launchd job fires at 1:20 AM. Docker Desktop and Postgres are not running at that hour. The result is:

- `Items stored: 0` — all DB writes fail silently (caught per-source).
- Digest crashes with no output — unhandled `OperationalError` from `repository.get_digest`.
- Only one digest email was ever sent (2026-05-17, a manual run).

### Fix

**New file: `scripts/run_digest.sh`**

```bash
#!/bin/bash
set -euo pipefail
cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"
/opt/homebrew/bin/docker compose up -d postgres
sleep 8
exec .venv/bin/python run.py digest-full
```

`set -euo pipefail` ensures the script aborts on any error rather than silently continuing. `sleep 8` gives Postgres time to become healthy. `exec` replaces the shell process so launchd's PID tracking stays clean.

**Updated plist: `~/Library/LaunchAgents/com.cybertrend.daily-digest.plist`**

- `ProgramArguments` → `["/bin/bash", "/Users/.../scripts/run_digest.sh"]`
- `StartCalendarInterval Hour` → `8` (was `1`)

After writing the plist, reload the agent:
```
launchctl unload ~/Library/LaunchAgents/com.cybertrend.daily-digest.plist
launchctl load   ~/Library/LaunchAgents/com.cybertrend.daily-digest.plist
```

### Constraints

- Docker path is `/opt/homebrew/bin/docker` (verified).
- `WorkingDirectory` stays set in the plist so relative paths in the script work.
- The old `scripts/daily_digest.sh` is superseded; it can be left in place or removed.

---

## Section 2 — Pipeline Reliability

### 2a. Accurate `sent` flag

**File:** `src/cybertrend/services/pipeline.py`

`send_daily_digest` currently returns `"sent": bool(self.email_sender)`, which is `True` whenever SMTP is configured — even if no email was sent because `digest_recipients` was empty.

Fix: track a boolean that is set to `True` only when `email_sender.send()` is actually called.

```python
sent = False
if self.email_sender and self.settings and self.settings.digest_recipients:
    self.email_sender.send(render_daily_digest(payload), self.settings.digest_recipients)
    sent = True
return {"digest_date": digest_date.isoformat(), "sent": sent}
```

### 2b. Digest persistence

**Files:** `src/cybertrend/services/pipeline.py`, `src/cybertrend/db/repository.py`

`digest_runs` table exists (Alembic head) but is never written to. `get_digest` always falls back to `build_digest_from_items` because there is no stored record.

Fix: after building the digest (and optionally sending it), save the payload.

In `pipeline.py`:
```python
if self.repository:
    self.repository.save_digest(payload)
```

New method in `repository.py`:
```python
def save_digest(self, payload: DigestPayload) -> None:
    values = {
        "digest_date": payload.digest_date,
        "payload": payload.model_dump(mode="json"),
        "sent_at": datetime.now(timezone.utc),
    }
    stmt = insert(DigestRunRecord).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[DigestRunRecord.digest_date],
        set_={k: v for k, v in values.items() if k != "digest_date"},
    )
    self.session.execute(stmt)
    self.session.commit()
```

Saving happens before the email send so the digest is persisted even if SMTP fails.

### 2c. SMTP immediate alerts for Critical items

**File:** `src/cybertrend/services/pipeline.py`

`IngestionService` enqueues Critical items to `alert_queue` (SQS). No SQS exists locally. `send_immediate_alert` exists in `PipelineService` but is never called from the collect path.

Fix: after `trigger_manual_run` finishes (local mode — no queue), call a new private method that queries today's Critical items and sends SMTP alerts for any that have not already been delivered.

```python
def _send_pending_critical_alerts(self) -> int:
    if not self.repository or not self.email_sender:
        return 0
    today = datetime.now(timezone.utc).date()
    items = self.repository.get_items_by_ingestion_date(today)
    sent = 0
    for item in items:
        if item.severity_label == "Critical":
            if self.send_immediate_alert(item.item_id):
                sent += 1
    return sent
```

Called at the end of `trigger_manual_run` when `self.queue` is `None`:
```python
if not self.queue:
    result["alerts_sent"] = self._send_pending_critical_alerts()
```

`send_immediate_alert` already checks `alert_already_sent` so this is idempotent.

---

## Section 3 — Phase 2 Structured Action Fields

### LLM output (`src/cybertrend/summaries_openai.py`)

Extend the JSON spec in `_build_user_prompt` with three controlled-vocabulary fields appended after `why_it_matters`:

```json
"action_type": "One of: Patch, Mitigate, Investigate, Monitor, Block, Review exposure",
"action_owner": "One of: Vuln management, SOC, IAM, Cloud team, Network team, AppSec, Endpoint team",
"timeframe": "One of: Now, Today, This week, Monitor"
```

Also extend the system prompt rules to require these fields never be empty.

Parse them in `OpenAISummaryProvider.summarize` and add to `llm_analysis`:
```python
"action_type":  _clean("action_type",  "Investigate"),
"action_owner": _clean("action_owner", "SOC"),
"timeframe":    _clean("timeframe",    "This week"),
```

Fallback values (`Investigate / SOC / This week`) are conservative and safe for any item where the LLM does not return a clear answer.

No model or DB changes — `llm_analysis` is already `Dict[str, Any]` stored as a JSON blob.

### Renderer (`src/cybertrend/email/render.py`)

Add a compact 3-chip row immediately after the exploitation badge and before the headline on every card. Render only when at least one of the three fields is present (graceful degradation for older stored items).

Visual shape (HTML):
```
[Patch]  [Network team]  [Today]
```

Chips use the existing severity colour palette:
- `action_type` chip: solid fill matching the card's severity colour.
- `action_owner` chip: neutral dark.
- `timeframe` chip: colour by urgency — `Now` uses Critical red, `Today` uses High orange, `This week` and `Monitor` use neutral.

Helper:
```python
def _action_chips(item: TrendItem) -> str:
    ...
```

Plain-text fallback: a single line `Action: {action_type} | Owner: {action_owner} | When: {timeframe}` inserted after the exploitation line.

---

## Section 4 — Tests

### `tests/test_pipeline.py`

- `send_daily_digest` with SMTP configured + non-empty recipients → `sent: True`.
- `send_daily_digest` with SMTP configured + empty recipients → `sent: False`.
- `send_daily_digest` calls `repository.save_digest` once regardless of send outcome.
- `trigger_manual_run` calls `_send_pending_critical_alerts` when `queue` is `None`.
- `_send_pending_critical_alerts` skips already-alerted items.

### `tests/test_ingestion.py` / `tests/test_openai_summarizer.py`

- LLM response with all three new fields → `llm_analysis` contains them.
- LLM response missing `action_type` → fallback `"Investigate"` used.

### `tests/test_email_render.py` (new or existing)

- Item with `action_type/action_owner/timeframe` in `llm_analysis` → chip row present in HTML.
- Item without those fields → chip row absent, no error.
- `timeframe = "Now"` → Critical-red chip colour.
- Plain-text fallback line rendered correctly.

---

## File Change Summary

| File | Change |
|------|--------|
| `scripts/run_digest.sh` | NEW — Docker startup + exec digest-full |
| `~/Library/LaunchAgents/com.cybertrend.daily-digest.plist` | Hour 8, new ProgramArguments |
| `src/cybertrend/services/pipeline.py` | Fix sent flag, save digest, send SMTP alerts |
| `src/cybertrend/db/repository.py` | Add `save_digest` method |
| `src/cybertrend/summaries_openai.py` | Add 3 action fields to prompt + llm_analysis |
| `src/cybertrend/email/render.py` | Render 3-chip action row per card |
| `tests/test_pipeline.py` | New cases for sent flag, digest save, alert path |
| `tests/test_smtp_email.py` | No change expected |
| `tests/test_ingestion.py` | New cases for action field fallbacks |

## Out of Scope

- Phase 3 (themes), Phase 4 (freshness badges), Phase 5 (watchlist).
- Backfilling the 2026-05-18 to 2026-05-31 item gap — RSS feeds have scrolled past those dates.
- Increasing `max_items_per_source` or `max_nvd_items`.
- Cloud/AWS deployment changes.
