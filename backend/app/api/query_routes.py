"""Read-side endpoints used by the dashboard to inspect stored telemetry."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_state
from app.models import TelemetryKind
from app.state import AppState

router = APIRouter(prefix="/query", tags=["query"])


@router.get("/stats")
def stats(state: AppState = Depends(get_state)) -> dict:
    """Per-table row counts, partition counts, and storage footprint."""
    return {
        kind.value: {
            "rows": tbl.row_count,
            "partitions": tbl.partition_count,
            "bytes": sum(tbl.memory_footprint().values()),
        }
        for kind, tbl in state.tables.items()
    }


@router.get("/events/{kind}")
def events(
    kind: TelemetryKind,
    limit: int = 100,
    start_ms: int | None = None,
    end_ms: int | None = None,
    state: AppState = Depends(get_state),
) -> list[dict]:
    """Return recent rows for a telemetry kind (time-bounded, limited)."""
    table = state.tables.get(kind)
    if table is None:
        raise HTTPException(status_code=404, detail=f"unknown kind {kind}")
    return table.query(start_ms=start_ms, end_ms=end_ms, limit=limit)


@router.get("/alerts")
def alerts(state: AppState = Depends(get_state)) -> list[dict]:
    return [a.model_dump() for a in state.alerts]
