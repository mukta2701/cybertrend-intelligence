# Daily Digest + r/pwnhub Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the collect+digest pipeline every day (not every 3rd day) and add r/pwnhub as a public RSS source.

**Architecture:** Two independent changes — one line in `pipeline.py` to add a new feed, one crontab update to change the schedule. The existing `RSSConnector` handles Reddit RSS without any code changes. The pipeline test asserts exact job counts and must be updated to match.

**Tech Stack:** Python 3.12, crontab (macOS)

---

## File Map

**Modified:**
- `src/cybertrend/services/pipeline.py` — add `reddit_pwnhub` entry to `DEFAULT_RSS_FEEDS`
- `tests/test_pipeline.py` — update expected job count from 8 to 9

**System (not in git):**
- macOS crontab — change `*/3` to `*` in day-of-month field

---

### Task 1: Add r/pwnhub to RSS feeds

**Files:**
- Modify: `src/cybertrend/services/pipeline.py:21-29`
- Modify: `tests/test_pipeline.py:26-31`

- [ ] **Step 1: Update the test to expect 9 jobs**

In `tests/test_pipeline.py`, replace lines 26-31:

```python
    assert result["queued_jobs"] == 9
    assert result["processed_jobs"] == 9
    assert result["stored_items"] == 18
    assert len(result["failed_jobs"]) == 0
    source_types = {job["source_type"] for job in ingestion.jobs}
    assert source_types == {"rss", "nvd"}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_pipeline.py::test_manual_run_processes_all_jobs_synchronously_without_queue -v
```

Expected: FAIL — `assert 8 == 9`

- [ ] **Step 3: Add reddit_pwnhub to DEFAULT_RSS_FEEDS**

In `src/cybertrend/services/pipeline.py`, replace:

```python
DEFAULT_RSS_FEEDS = {
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
    "sans_isc": "https://isc.sans.edu/rssfeed_full.xml",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "securityweek": "https://www.securityweek.com/feed/",
    "tenable": "https://www.tenable.com/security/research/feed",
}
```

With:

```python
DEFAULT_RSS_FEEDS = {
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
    "sans_isc": "https://isc.sans.edu/rssfeed_full.xml",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "securityweek": "https://www.securityweek.com/feed/",
    "tenable": "https://www.tenable.com/security/research/feed",
    "reddit_pwnhub": "https://www.reddit.com/r/pwnhub/.rss",
}
```

- [ ] **Step 4: Run the full test suite**

```bash
pytest tests/test_pipeline.py -v
```

Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/services/pipeline.py tests/test_pipeline.py
git commit -m "feat: add r/pwnhub as public RSS source"
```

---

### Task 2: Switch cron to daily

**Files:**
- System: macOS crontab (not in git)

- [ ] **Step 1: Install the updated crontab**

Run this single command — it replaces the schedule in place:

```bash
(crontab -l | sed 's|0 9 \*/3 \* \*|0 9 * * *|') | crontab -
```

- [ ] **Step 2: Verify the new crontab**

```bash
crontab -l
```

Expected output contains:
```
0 9 * * * cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation" && .venv/bin/python run.py collect >> /tmp/cybertrend.log 2>&1 && .venv/bin/python run.py digest >> /tmp/cybertrend.log 2>&1
```

The `*/3` should be gone, replaced by a plain `*`.
