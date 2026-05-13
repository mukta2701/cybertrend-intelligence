# Cybertrend Operations

## Secrets

Store these values in AWS Secrets Manager after deployment:

- `API_KEY`
- `NVD_API_KEY`
- `TENABLE_ACCESS_KEY`
- `TENABLE_SECRET_KEY`
- `LLM_API_KEY`

SES sender/domain verification is handled outside the application. Keep the `SES_FROM_EMAIL`
domain aligned with the verified SES identity.

## Schedules

- Collection: every 15 minutes.
- Daily digest: 07:30 Europe/London.
- Source-quality refresh: Friday 08:00 Europe/London.

## Alerting

Immediate alerts are sent for `Critical` items. A critical item is either score `>= 85` or a KEV
item with strong exploit evidence. High and Medium items are digest-only unless promoted later.

CloudWatch alarms cover Lambda errors and SQS DLQ depth. SES rendering failures are routed to SNS.

## Runbook

1. Check CloudWatch alarm details and the relevant Lambda log group.
2. Inspect SQS DLQs for failed source jobs or alert jobs.
3. Use `GET /sources/health` for connector lag and failure streaks.
4. Use `GET /scores/explain/{item_id}` before adjusting thresholds.
5. Re-drive DLQ messages only after the underlying connector or payload issue is fixed.

## Local Commands

```bash
docker compose up -d postgres
alembic upgrade head
pytest
ruff check .
pyright
cdk synth
```

