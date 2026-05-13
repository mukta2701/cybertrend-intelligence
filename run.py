#!/usr/bin/env python3
"""Local CLI runner for Cybertrend."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_ROOT = PROJECT_ROOT / "src"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        print("Usage: python run.py [collect|digest|api]")
        print()
        print("  collect   Fetch all RSS feeds and store scored items")
        print("  digest    Build and deliver today's digest")
        print("  api       Start the local API on http://127.0.0.1:8000")
        sys.exit(0)

    command = sys.argv[1]
    if command not in {"collect", "digest", "api"}:
        print(f"Unknown command: {command!r}")
        sys.exit(1)

    from cybertrend.config import get_settings
    from cybertrend.services.pipeline import PipelineService

    settings = get_settings()
    pipeline = PipelineService.from_settings(settings)

    if command == "collect":
        result = pipeline.trigger_manual_run()
        print(f"Run ID:       {result['run_id']}")
        print(f"Jobs done:    {result['processed_jobs']} / {result['queued_jobs']}")
        print(f"Items stored: {result['stored_items']}")
        if result["failed_jobs"]:
            print(f"Failures:     {result['failed_jobs']}")

    elif command == "digest":
        today = datetime.now(timezone.utc).date()
        result = pipeline.send_daily_digest(today)
        print(f"Digest {result['digest_date']} - sent: {result['sent']}")

    elif command == "api":
        import uvicorn

        from cybertrend.api import create_app

        app = create_app(pipeline=pipeline, api_key=settings.api_key)
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
