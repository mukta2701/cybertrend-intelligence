from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from cybertrend.config import get_settings
from cybertrend.models import SourcePolicy
from cybertrend.services.pipeline import PipelineService


def create_app(
    pipeline: Optional[PipelineService] = None, api_key: Optional[str] = None
) -> FastAPI:
    settings = get_settings()
    active_api_key = api_key if api_key is not None else settings.api_key
    active_pipeline = pipeline or PipelineService.from_settings(settings)

    def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
        if not active_api_key:
            return
        if x_api_key != active_api_key:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    app = FastAPI(title="Cybertrend Intelligence API", version="0.1.0")

    @app.post("/runs/manual", dependencies=[Depends(require_api_key)])
    def manual_run():
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
