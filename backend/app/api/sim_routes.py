"""Endpoints that drive the simulator: inject a scenario, then run detection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.api.deps import get_state
from app.correlation import Detector
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
def detect(detector: Detector = Depends(get_detector)) -> DetectResult:
    """Run the correlation rules and return any newly raised alerts."""
    new = detector.run()
    return DetectResult(new_alerts=[a.model_dump() for a in new])
