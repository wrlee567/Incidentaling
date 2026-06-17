"""AI-powered endpoints: alert enrichment and (future) investigation, anomaly detection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.ai import features
from app.api.deps import get_state
from app.models.ai_models import AlertEnrichment, EnrichRequest
from app.state import AppState

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/enrich", response_model=AlertEnrichment)
async def enrich(body: EnrichRequest, state: AppState = Depends(get_state)) -> AlertEnrichment:
    """Enrich a specific alert with Claude's analysis.

    Looks up the alert by ID, gathers correlated telemetry evidence,
    and asks Claude to produce a plain-English explanation plus recommended actions.
    Returns mock data when ANTHROPIC_API_KEY is not set.
    """
    alert = next((a for a in state.alerts if a.alert_id == body.alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert {body.alert_id!r} not found")

    enrichment = await features.enrich_alert(alert, state)

    # Write back to the alert object so future GET /query/alerts includes it
    alert.ai_explanation = enrichment.explanation
    alert.ai_severity_justification = enrichment.severity_justification
    alert.ai_recommended_actions = enrichment.recommended_actions
    alert.ai_threat_intel = enrichment.threat_intel

    return enrichment


# -- Future phases (not yet implemented) -------------------------------------

@router.post("/investigate", status_code=501)
async def investigate() -> dict:
    """[Phase 2] Agentic investigation — Claude autonomously queries the SIEM."""
    return {"detail": "Not implemented yet"}


@router.post("/anomalies", status_code=501)
async def anomalies() -> dict:
    """[Phase 3] LLM-based anomaly detection beyond rule signatures."""
    return {"detail": "Not implemented yet"}


@router.post("/query", status_code=501)
async def nl_query() -> dict:
    """[Phase 4] Natural language SIEM query interface."""
    return {"detail": "Not implemented yet"}


@router.post("/playbook", status_code=501)
async def playbook() -> dict:
    """[Phase 5] Dynamic playbook generation for a given alert."""
    return {"detail": "Not implemented yet"}
