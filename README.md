# Cybertrend

Cybertrend is a production-shaped cybersecurity trend intelligence service. It ingests Reddit,
security RSS, and vulnerability feeds, enriches CVEs, deduplicates signals, scores urgency and
confidence, and sends immediate SES alerts plus a daily digest.

## Local Setup

The deployment target is Python 3.12 on AWS Lambda. For local development:

```bash
cp .env.example .env
docker compose up -d postgres
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev,infra]"
alembic upgrade head
pytest
```

This workstation may not have Python 3.12 available; CI is configured to verify against Python
3.12.

## Architecture

- EventBridge Scheduler triggers collection every 15 minutes.
- Collector Lambda enqueues source jobs onto SQS.
- Worker Lambdas collect, normalize, enrich, dedupe, score, summarize, and persist trend items.
- Alert Lambda sends immediate SES alerts for critical items.
- Digest Lambda sends the daily Europe/London digest at 07:30.
- FastAPI runs behind API Gateway for manual runs, item search, source health, source policy, and
  score explanations.

See [docs/operations.md](docs/operations.md) for deployment and operations guidance.

