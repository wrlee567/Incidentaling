"""Endpoints that drive the simulator: inject a scenario, then run detection."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.ai.features import auto_enrich
from app.api.deps import get_state
from app.correlation import Detector
from app.models.events import Alert
from app.simulation import Difficulty, Scenario, SimulationEngine
from app.state import AppState

router = APIRouter(tags=["simulation"])


class SimulateResult(BaseModel):
    scenario: str
    injected: int


class DetectResult(BaseModel):
    new_alerts: list[dict]


def get_detector(request: Request) -> Detector:
    return request.app.state.detector


@router.post("/simulate", response_model=SimulateResult)
def simulate(
    scenario: Scenario,
    difficulty: Difficulty = Difficulty.MEDIUM,
    seed: int | None = None,
    state: AppState = Depends(get_state),
) -> SimulateResult:
    """Generate a scenario's telemetry and ingest it straight into the store."""
    eng = SimulationEngine(seed=seed)
    envelopes = eng.build_scenario(scenario, difficulty)
    for env in envelopes:
        state.ingest(env)
    return SimulateResult(scenario=scenario.value, injected=len(envelopes))


@router.post("/detect", response_model=DetectResult)
async def detect(
    detector: Detector = Depends(get_detector),
    state: AppState = Depends(get_state),
) -> DetectResult:
    """Run the correlation rules and return any newly raised alerts.

    Each new alert is automatically enriched by Claude in the background.
    The enrichment fields (ai_explanation, etc.) appear on the alert objects
    within a few seconds and are returned by subsequent GET /query/alerts calls.
    """
    new = detector.run()
    for alert in new:
        asyncio.create_task(auto_enrich(alert, state))
    return DetectResult(new_alerts=[a.model_dump() for a in new])
