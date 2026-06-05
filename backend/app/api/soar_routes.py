"""SOAR endpoints: trigger playbooks for alerts and inspect workflow runs."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_state
from app.state import AppState

router = APIRouter(prefix="/soar", tags=["soar"])


@router.post("/respond")
def respond(state: AppState = Depends(get_state)) -> dict:
    """Launch the matching playbook for every alert that has not been responded to."""
    launched = state.respond()
    return {"launched": launched}


@router.get("/runs")
def runs(state: AppState = Depends(get_state)) -> list[dict]:
    rows = state.history.conn.execute(
        "SELECT run_id, name, status, created_ts, updated_ts FROM workflow_runs ORDER BY created_ts"
    ).fetchall()
    return [dict(r) for r in rows]


@router.get("/runs/{run_id}")
def run_detail(run_id: str, state: AppState = Depends(get_state)) -> dict:
    run = state.history.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown run")
    events = [
        {"seq": e["seq"], "ts": e["ts"], "type": e["type"], "step_id": e["step_id"],
         "payload": json.loads(e["payload"])}
        for e in state.history.events(run_id)
    ]
    return {"run": dict(run), "events": events}


@router.get("/environment")
def environment(state: AppState = Depends(get_state)) -> dict:
    """Current state of the simulated enterprise environment (containment actions)."""
    env = state.environment
    return {
        "isolated_hosts": sorted(env.isolated_hosts),
        "terminated_on": sorted(env.terminated_on),
        "blocked_ips": sorted(env.blocked_ips),
        "segregated_subnets": sorted(env.segregated_subnets),
        "locked_accounts": sorted(env.locked_accounts),
        "password_resets": sorted(env.password_resets),
        "mfa_enforced": sorted(env.mfa_enforced),
        "exfil_reviews": env.exfil_reviews,
        "actions": env.actions,
    }
