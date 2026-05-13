# How Cybertrend Intelligence Works

A personal reference for understanding what this system does, why it was built this way, and how to operate it.

---

## What It Does

Every 3 days, Cybertrend automatically:
1. Fetches the latest cybersecurity news from 8 sources
2. Scores each item by threat severity
3. Sends each article to GPT-4o-mini for structured analysis
4. Emails a formatted digest to your inbox grouped by severity (Critical / High / Medium)

You can also trigger any step manually at any time.

---

## The Pipeline — Step by Step

```
Sources (RSS + NVD)
       ↓
   Collect & Deduplicate
       ↓
   Score (rules-based)
       ↓
   Enrich (NVD CVE data, EPSS, CISA KEV)
       ↓
   Summarize (GPT-4o-mini, 10 parallel workers)
       ↓
   Store (PostgreSQL)
       ↓
   Send Digest (Gmail SMTP)
```

### 1. Collect

The pipeline fetches from 8 sources in parallel:

| Source | Type | What it covers |
|--------|------|----------------|
| BleepingComputer | RSS | Breaking vulnerabilities, ransomware, breach reports |
| The Hacker News | RSS | CVEs, exploits, threat actor campaigns |
| Krebs on Security | RSS | In-depth investigative security journalism |
| SANS ISC | RSS | Daily practitioner diary entries |
| Dark Reading | RSS | Enterprise security news and analysis |
| SecurityWeek | RSS | Vulnerability disclosures, breach news |
| Tenable Research | RSS | Researcher-discovered CVEs |
| NVD / NIST | API | All CVEs published in the last 24 hours |

Reddit was the original source but was replaced — Reddit blocked all RSS access with HTTP 403 errors. These 7 RSS sources are all publicly accessible and professionally curated.

### 2. Deduplicate

Before storing, each item gets a `dedupe_key` — a fingerprint based on shared CVE IDs or a canonical URL (tracking parameters stripped). If the same vulnerability appears on BleepingComputer and The Hacker News, only one copy is stored.

### 3. Score

Every item is scored 0–100 using a rules-based algorithm that weighs:

- **CVSS base score** — how severe the vulnerability is technically
- **EPSS probability** — likelihood of exploitation in the next 30 days (from FIRST.org)
- **CISA KEV flag** — whether CISA has confirmed active exploitation
- **Tenable VPR** — Tenable's own risk score (if available)
- **Exploit evidence** — keywords in the article (ransomware, active exploitation, PoC, etc.)
- **Engagement** — how much community discussion the item generated

The score determines the severity label:
- **Critical** — score ≥ 80
- **High** — score 60–79
- **Medium** — score 40–59
- Below 40 — filtered out of the digest

### 4. Enrich

For items with CVE IDs, the pipeline queries:
- **NVD API** — for CVSS scores and references
- **EPSS API** (FIRST.org) — for exploitation probability percentile
- **CISA KEV feed** — to check if the CVE is on the Known Exploited Vulnerabilities list

This enrichment is what makes the scoring authoritative — it's not just based on what the article says, but on real vulnerability data.

### 5. Summarize (GPT-4o-mini)

Each item is sent to OpenAI's GPT-4o-mini with a strict structured prompt. The model returns 8 specific fields:

| Field | What it tells you |
|-------|-------------------|
| `headline` | One-line summary: Vendor Product — issue and attacker outcome |
| `affected_assets` | Specific products, versions, or configurations at risk |
| `vulnerability` | Exactly what is broken and in which component |
| `threat` | What an attacker can concretely do (RCE, auth bypass, data theft, etc.) |
| `exploitation_status` | Actively exploited / PoC available / Exploitation likely / Unknown |
| `organizational_risk` | Real-world business impact if left unpatched |
| `recommended_action` | The most practical next step (patch, restrict, monitor) |
| `why_it_matters` | Why a security team should care right now |

**Important design decisions in the prompt:**
- The model is instructed to use only information in the article — no invention
- Generic phrases like "organizations should stay vigilant" are explicitly banned
- If a detail isn't in the article, the model writes "Not stated" — not a guess
- A prompt injection defence was added: if article content contains instructions to override the model's rules, they are ignored

Article content is sanitized before being sent to OpenAI — emails, URLs, and IP addresses are redacted. This is both a privacy control and a safety measure.

10 articles are processed in parallel (ThreadPoolExecutor), reducing the total summarization time from ~15 minutes to ~2 minutes.

### 6. Store

Everything is stored in a local PostgreSQL 16 database (running in Docker). The main table is `trend_items` with columns for all scoring data, enrichment data, and the `llm_analysis` JSONB column holding the 8-field GPT output.

The digest date is based on `created_at` (when the item was ingested), not `published_at` (when the article was originally published). This ensures today's collect run shows up in today's digest, even if the articles were technically published yesterday.

### 7. Send Digest

The digest email is rendered in two formats simultaneously:
- **HTML** — formatted with dark navy header, colour-coded severity banners (red/orange/yellow), white cards with exploitation badges, CVSS/EPSS/score pills, action box
- **Plain text** — fallback for email clients that don't render HTML

The subject line includes the count of items per severity, e.g.:
```
Cyber Threat Digest — May 13, 2026 | 3 Critical, 7 High, 12 Medium
```

For any Critical item with a score ≥ 90, an immediate alert email is also sent separately with a red header.

---

## Security Decisions

Several security issues were identified and fixed during a hardening audit:

| Issue | Fix Applied |
|-------|-------------|
| API key comparison vulnerable to timing attacks | Replaced with `secrets.compare_digest()` |
| FastAPI auto-generated docs exposed at `/docs` | Disabled `docs_url`, `redoc_url`, `openapi_url` |
| `/runs/manual` endpoint could be spammed | Rate-limited to 1 trigger per 5 minutes |
| No API key configured → silent pass-through | Now returns HTTP 503 instead |
| Invalid cursor value → unhandled ValueError, stack trace in response | Wrapped in try/except, invalid cursor treated as no cursor |
| SMTP STARTTLS not verifying server certificate | Now passes `ssl.create_default_context()` to `starttls()` |
| LLM prompt could be hijacked by article content | Added explicit prompt injection defence in SYSTEM_PROMPT |
| `typeguard` dependency had known vulnerability | Pinned to `>=4.5.1` |

---

## How to Run It Manually

```bash
# Activate the virtual environment
cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"

# Fetch all sources and score/summarize items
.venv/bin/python run.py collect

# Build and send today's digest
.venv/bin/python run.py digest

# Re-summarize today's items with GPT (if summaries look stale)
.venv/bin/python run.py rescan

# Start the local REST API on http://127.0.0.1:8000
.venv/bin/python run.py api
```

## Automatic Schedule

A cron job runs collect + digest every 3 days at 9am:

```
0 9 */3 * * cd "..." && .venv/bin/python run.py collect && .venv/bin/python run.py digest
```

To view or edit it: `crontab -e`
To check the log: `cat /tmp/cybertrend.log`

**Note:** Your Mac must be on and awake at 9am for the cron to fire.

---

## Project Structure

```
src/cybertrend/
├── api.py                  # FastAPI REST endpoints
├── config.py               # Settings loaded from .env
├── dedupe.py               # URL canonicalisation and CVE-based deduplication
├── models.py               # Pydantic data models (TrendItem, DigestPayload, etc.)
├── scoring.py              # Rules-based criticality scoring
├── summaries.py            # HybridSummaryProvider (rules-first + optional LLM)
├── summaries_openai.py     # GPT-4o-mini structured analysis
├── connectors/
│   ├── rss.py              # RSS feed fetcher
│   ├── nvd.py              # NVD CVE API client
│   ├── epss.py             # EPSS exploitation probability client
│   └── kev.py              # CISA KEV feed client
├── db/
│   ├── models.py           # SQLAlchemy ORM models
│   └── repository.py       # All database read/write operations
├── email/
│   ├── render.py           # HTML + plain text email renderer
│   └── smtp.py             # Gmail SMTP sender
└── services/
    ├── pipeline.py         # Orchestrates the full collect→score→summarize→store flow
    └── ingestion.py        # Per-source ingestion logic and trust scoring
```

---

## Key Design Choices and Why

**Why rules-based scoring instead of letting GPT decide severity?**
GPT can be inconsistent and can be influenced by how alarming an article sounds rather than actual exploitability data. The rules-based scorer uses hard signals (CISA KEV confirmed = Critical, EPSS > 90th percentile = very likely exploited) that can't be talked up by sensationalist writing.

**Why does exploitation status override GPT's answer?**
If CISA has confirmed a CVE is being actively exploited in the wild, that's a harder signal than what any article says. The `_derive_exploitation()` function checks KEV flag and EPSS first — GPT's `exploitation_status` field is only used as a fallback.

**Why `created_at` for digest filtering instead of `published_at`?**
Articles are often published the day before they're ingested (especially overnight news). Using `published_at` meant yesterday's articles wouldn't appear in today's digest. Using `created_at` ensures everything collected today is in today's digest.

**Why 10 parallel GPT workers?**
Each GPT call takes ~3–5 seconds. With 50–100 articles, sequential processing would take 15+ minutes. 10 workers reduce this to ~2 minutes with no quality loss.
