"""Pydantic request/response types for the AI enrichment endpoints."""

from __future__ import annotations

from pydantic import BaseModel


class AlertEnrichment(BaseModel):
    """The structured analysis Claude produces for a single alert."""

    alert_id: str
    explanation: str
    severity_justification: str
    recommended_actions: list[str]
    threat_intel: str
    confidence: float  # 0.0–1.0


class EnrichRequest(BaseModel):
    alert_id: str
