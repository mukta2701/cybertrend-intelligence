#!/bin/bash
set -euo pipefail
cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"
/opt/homebrew/bin/docker compose up -d postgres
for _ in {1..60}; do
    if /opt/homebrew/bin/docker compose exec -T postgres pg_isready -U cybertrend -d cybertrend -q; then
        exec .venv/bin/python run.py digest-full
    fi
    sleep 1
done
echo "Postgres did not become ready within 60 seconds" >&2
exit 1
