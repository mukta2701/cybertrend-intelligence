#!/bin/bash
set -euo pipefail
cd "/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"
/opt/homebrew/bin/docker compose up -d postgres
sleep 8
exec .venv/bin/python run.py digest-full
