"""Hybrid ingestion endpoints.

* ``POST /ingest/push``   — low-latency path for HIGH/CRITICAL events. Written to the
  store immediately and (later) handed to the SOAR engine. Rejects routine traffic to
  keep the hot path reserved for what actually needs real-time treatment.

* ``POST /ingest/spool``  — an agent appends routine, lower-severity telemetry to its
  local buffer. The server has NOT ingested it yet.

* ``POST /ingest/pull``   — the server-controlled poll: drain a batch from the spool
  into the store. In production a background worker calls this on a timer; exposing it
  as an endpoint makes the batch/backpressure behavior observable and testable.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_state
from app.models import TelemetryEnvelope
from app.state import PUSH_REQUIRED_SEVERITY, AppState

router = APIRouter(prefix="/ingest", tags=["ingestion"])


class IngestResult(BaseModel):
    accepted: int
    transport: str


class SpoolResult(BaseModel):
    spooled: bool
    depth: int
    dropped: int


@router.post("/push", response_model=IngestResult)
def push(env: TelemetryEnvelope, state: AppState = Depends(get_state)) -> IngestResult:
    """Real-time push path, reserved for high-severity events."""
    if env.severity < PUSH_REQUIRED_SEVERITY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "push path is reserved for HIGH+ severity; "
                "route routine telemetry through /ingest/spool"
            ),
        )
    try:
        state.ingest(env)
    except Exception as exc:  # invalid payload -> 422-style rejection
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IngestResult(accepted=1, transport="push")


@router.post("/spool", response_model=SpoolResult)
def spool(env: TelemetryEnvelope, state: AppState = Depends(get_state)) -> SpoolResult:
    """Agent-side append to the local buffer (routine telemetry)."""
    ok = state.pull_buffer.offer(env)
    return SpoolResult(spooled=ok, depth=state.pull_buffer.depth, dropped=state.pull_buffer.dropped)


@router.post("/pull", response_model=IngestResult)
def pull(max_batch: int = 500, state: AppState = Depends(get_state)) -> IngestResult:
    """Server-controlled batch drain of the spool into the store."""
    batch = state.pull_buffer.drain(max_batch)
    accepted = 0
    for env in batch:
        try:
            state.ingest(env)
            accepted += 1
        except Exception:
            # A malformed routine log is dropped rather than stalling the batch.
            continue
    return IngestResult(accepted=accepted, transport="pull")
