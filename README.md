# Cybertrend Intelligence

A personal cybersecurity threat intelligence pipeline that automatically collects, scores, and summarises the latest security news and CVEs — then emails you a formatted daily digest.

## What It Does

- Fetches from **7 RSS feeds** (BleepingComputer, The Hacker News, Krebs on Security, SANS ISC, Dark Reading, SecurityWeek, Tenable Research) and the **NVD CVE API**
- Scores each item by exploitability using CVSS, EPSS, CISA KEV, and exploit evidence
- Summarises every article with GPT-4o-mini into 8 structured fields (vulnerability, threat, affected assets, recommended action, and more)
- Sends a formatted HTML digest to your inbox grouped by severity: Critical / High / Medium
- Sends immediate alerts for Critical items scoring ≥ 90

## Local Setup

Requires Python 3.12, Docker, and a Gmail account with an App Password.

```bash
cp .env.example .env          # fill in your credentials
docker compose up -d postgres
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
pytest                        # verify everything works
```

## Running It

```bash
# Fetch all sources, score and summarise items
python run.py collect

# Build and send today's digest to your email
python run.py digest

# Re-summarise today's items if GPT output looks stale
python run.py rescan

# Start the local REST API on http://127.0.0.1:8000
python run.py api
```

## Automatic Schedule

Two cron jobs keep collection separate from email delivery so the digest does not wait for a slow collection run (set up with `crontab -e`):

```
0 8 * * * cd "/path/to/project" && .venv/bin/python run.py collect >> /tmp/cybertrend.log 2>&1
0 9 * * * cd "/path/to/project" && .venv/bin/python run.py digest >> /tmp/cybertrend.log 2>&1
```

Logs go to `/tmp/cybertrend.log`.

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `API_KEY` | Secret key for the REST API |
| `SMTP_USER` / `SMTP_PASSWORD` | Gmail address + App Password |
| `SMTP_TIMEOUT_SECONDS` | SMTP network timeout, default `30` |
| `ALERT_RECIPIENTS` | Email(s) for immediate critical alerts |
| `DIGEST_RECIPIENTS` | Email(s) for the daily digest |
| `MAX_ITEMS_PER_SOURCE` / `MAX_NVD_ITEMS` | Caps expensive enrichment and OpenAI work per collection run |
| `LLM_API_KEY` | OpenAI API key for GPT-4o-mini summarisation |
| `NVD_API_KEY` | Optional — free key from nvd.nist.gov |

## Architecture

```
RSS Feeds + NVD API
       ↓
   Collect & Deduplicate
       ↓
   Score (CVSS + EPSS + KEV + exploit signals)
       ↓
   Enrich (NVD, EPSS, CISA KEV)
       ↓
   Summarise (GPT-4o-mini, 10 parallel workers)
       ↓
   Store (PostgreSQL)
       ↓
   Email Digest (Gmail SMTP)
```

The project also includes an AWS CDK stack (`infra/`) for cloud deployment with Lambda, SQS, RDS, and EventBridge — but the local setup above is fully self-contained.

## Docs

- [How It Works](docs/HOW_IT_WORKS.md) — full explanation of every pipeline stage, design decisions, and security hardening
- [Operations](docs/operations.md) — runbook and deployment notes

## Security

- API key authentication with timing-safe comparison
- SMTP with verified TLS (`ssl.create_default_context()`)
- GPT prompt hardened against injection from article content
- All credentials loaded from `.env` (never committed)
