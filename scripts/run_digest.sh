#!/bin/bash
set -euo pipefail
cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"
/opt/homebrew/bin/docker compose up -d postgres
until /opt/homebrew/bin/pg_isready -h localhost -q; do sleep 1; done
exec .venv/bin/python run.py digest-full
