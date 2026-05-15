#!/bin/bash
# Daily digest runner — called by launchd at 8am

PROJECT="/Users/m1ghty/Documents/Cybersecurity Trend Intelligence Automation"
PYTHON="$PROJECT/.venv/bin/python"
LOG="$PROJECT/logs/daily_digest.log"

mkdir -p "$PROJECT/logs"

{
  echo "=============================="
  echo "Started: $(date)"

  cd "$PROJECT" || exit 1

  # Load .env so API keys and DB URL are available
  set -o allexport
  source "$PROJECT/.env"
  set +o allexport

  export PYTHONPATH="$PROJECT/src"

  echo "--- collect ---"
  "$PYTHON" run.py collect

  echo "--- digest ---"
  "$PYTHON" run.py digest

  echo "Finished: $(date)"
} >> "$LOG" 2>&1
