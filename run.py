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
        print("Usage: python run.py [collect|digest|digest-full|rescan|api]")
        print()
        print("  collect      Fetch all RSS feeds and store scored items")
        print("  digest       Build and deliver today's digest")
        print("  digest-full  collect + digest in one shot (used by scheduler)")
        print("  rescan       Re-summarize today's stored items with GPT (fixes stale summaries)")
        print("  api          Start the local API on http://127.0.0.1:8000")
        sys.exit(0)

    command = sys.argv[1]
    if command not in {"collect", "digest", "digest-full", "rescan", "api"}:
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
        source_stats = result.get("source_stats") or []
        if source_stats:
            print("Source timings:")
            for stat in source_stats:
                source_name = stat.get("source_name") or stat.get("source_type") or "unknown"
                elapsed = stat.get("elapsed_seconds", 0)
                status = "ok" if stat.get("success") else "failed"
                fetched = stat.get("fetched_items", 0)
                processed = stat.get("processed_items", 0)
                stored = stat.get("stored_items", 0)
                skipped = stat.get("skipped_summaries", 0)
                limited = stat.get("limited_items", 0)
                print(
                    f"  {source_name}: {status}, {elapsed:.2f}s, "
                    f"fetched {fetched}, processed {processed}, stored {stored}, "
                    f"skipped summaries {skipped}, limited {limited}"
                )
        if result["failed_jobs"]:
            print(f"Failures:     {result['failed_jobs']}")

    elif command == "digest":
        today = datetime.now(timezone.utc).date()
        result = pipeline.send_daily_digest(today)
        print(f"Digest {result['digest_date']} - sent: {result['sent']}")

    elif command == "digest-full":
        print("=== collect ===")
        result = pipeline.trigger_manual_run()
        print(f"Items stored: {result['stored_items']}")
        print("=== digest ===")
        today = datetime.now(timezone.utc).date()
        result = pipeline.send_daily_digest(today)
        print(f"Digest {result['digest_date']} - sent: {result['sent']}")

    elif command == "rescan":
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from cybertrend.summaries import HybridSummaryProvider
        from cybertrend.summaries_openai import OpenAISummaryProvider

        WORKERS = 10

        today = datetime.now(timezone.utc).date()
        items = pipeline.repository.get_items_by_ingestion_date(today)
        if not items:
            print("No items found for today.")
            sys.exit(0)

        llm = OpenAISummaryProvider(api_key=settings.llm_api_key) if settings.llm_api_key else None
        summarizer = HybridSummaryProvider(llm_provider=llm)

        counter_lock = threading.Lock()
        completed = 0
        total = len(items)
        print(f"Rescanning {total} items with {WORKERS} parallel workers...")

        def process(item):
            return summarizer.summarize(item, {})

        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = {executor.submit(process, item): item for item in items}
            for future in as_completed(futures):
                refreshed = future.result()
                pipeline.repository.upsert_item(refreshed)
                with counter_lock:
                    completed += 1
                    print(f"  [{completed}/{total}]", end="\r")

        print(f"\nRescan complete — {completed} items re-summarized.")

    elif command == "api":
        import uvicorn

        from cybertrend.api import create_app

        app = create_app(pipeline=pipeline, api_key=settings.api_key)
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
