from __future__ import annotations

import secrets
import threading
import time
from datetime import date, datetime
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from cybertrend.config import get_settings
from cybertrend.models import SourcePolicy
from cybertrend.services.pipeline import PipelineService

# Simple in-memory rate limiter for /runs/manual (max 1 trigger per 5 minutes)
_last_manual_run: float = 0.0
_rate_limit_lock = threading.Lock()
_MANUAL_RUN_COOLDOWN = 300  # seconds


def create_app(
    pipeline: Optional[PipelineService] = None, api_key: Optional[str] = None
) -> FastAPI:
    settings = get_settings()
    active_api_key = api_key if api_key is not None else settings.api_key
    active_pipeline = pipeline or PipelineService.from_settings(settings)

    # Docs disabled — no unauthenticated API exploration
    app = FastAPI(
        title="Cybertrend Intelligence API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
        if not active_api_key:
            raise HTTPException(status_code=503, detail="API key not configured on server")
        # Constant-time comparison prevents timing attacks
        if not secrets.compare_digest(x_api_key or "", active_api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    @app.post("/runs/manual", dependencies=[Depends(require_api_key)])
    def manual_run():
        global _last_manual_run
        with _rate_limit_lock:
            now = time.time()
            if now - _last_manual_run < _MANUAL_RUN_COOLDOWN:
                wait = int(_MANUAL_RUN_COOLDOWN - (now - _last_manual_run))
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limited — try again in {wait}s",
                )
            _last_manual_run = now
        return active_pipeline.trigger_manual_run()

    @app.get("/items", dependencies=[Depends(require_api_key)])
    def list_items(
        severity: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = Query(default=50, ge=1, le=200),
        cursor: Optional[str] = None,
    ):
        return active_pipeline.list_items(
            severity=severity,
            source=source,
            since=since,
            limit=limit,
            cursor=cursor,
        )

    @app.get("/digests/{digest_date}", dependencies=[Depends(require_api_key)])
    def get_digest(digest_date: date):
        return active_pipeline.get_digest(digest_date)

    @app.get("/sources/health", dependencies=[Depends(require_api_key)])
    def source_health():
        return active_pipeline.get_source_health()

    @app.put("/sources/policy", dependencies=[Depends(require_api_key)])
    def update_policy(policy: SourcePolicy):
        return active_pipeline.update_source_policy(policy)

    @app.get("/scores/explain/{item_id}", dependencies=[Depends(require_api_key)])
    def explain_score(item_id: str):
        return active_pipeline.explain_score(item_id)

    return app
