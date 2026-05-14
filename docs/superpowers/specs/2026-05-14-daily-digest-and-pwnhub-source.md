# Daily Digest + r/pwnhub Source Design

**Date:** 2026-05-14

## Summary

Two small changes to the running local pipeline:

1. Switch the cron schedule from every 3rd day to every day.
2. Add r/pwnhub as a public RSS source.

## Change 1: Daily cron

**Current crontab entry:**
```
0 9 */3 * * cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation" && .venv/bin/python run.py collect >> /tmp/cybertrend.log 2>&1 && .venv/bin/python run.py digest >> /tmp/cybertrend.log 2>&1
```

**Target crontab entry:**
```
0 9 * * * cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation" && .venv/bin/python run.py collect >> /tmp/cybertrend.log 2>&1 && .venv/bin/python run.py digest >> /tmp/cybertrend.log 2>&1
```

Change: `*/3` → `*` in the day-of-month field. Time (09:00) and log path unchanged.

## Change 2: r/pwnhub RSS source

**File:** `src/cybertrend/services/pipeline.py`

Add one entry to `DEFAULT_RSS_FEEDS`:
```python
"reddit_pwnhub": "https://www.reddit.com/r/pwnhub/.rss",
```

- Uses the existing `RSSConnector` — no new code needed.
- No credentials required (public subreddit RSS).
- Trust score defaults to `0.70` via the existing fallback in `_source_trust`.
- No schema or migration changes needed.

## Out of scope

- No trust score override for r/pwnhub (leave at 0.70 default).
- No changes to digest schedule time.
- No changes to other sources.
