"""Pydantic request/response types for the AI enrichment endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


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


# ---------------------------------------------------------------------------
# Tier-3 Incident Response investigation models
# ---------------------------------------------------------------------------

class TriageAssessment(BaseModel):
    threat_objectives: str
    severity: str
    status: str
    compromised_assets: list[str] = Field(default_factory=list)


class PivotTimelineEntry(BaseModel):
    timestamp: str
    source_environment: str
    asset_or_identity: str
    activity_or_artifact: str
    correlation_pivot_point: str


class AutomatedAction(BaseModel):
    action: str
    activity_name: str
    params: dict = Field(default_factory=dict)
    confidence_score: float = Field(..., ge=0.90, le=1.0)
    rationale: str


class AnalystValidatedAction(BaseModel):
    action: str
    priority: str
    confidence_score: float = Field(..., ge=0.0, lt=0.90)
    rationale: str


class RemediationPlaybook(BaseModel):
    automated_actions: list[AutomatedAction] = Field(default_factory=list)
    analyst_validated_actions: list[AnalystValidatedAction] = Field(default_factory=list)


class NistIrPhase(BaseModel):
    phase: str
    activities: list[str] = Field(default_factory=list)
    status: str


class CriDiagnosticStatement(BaseModel):
    control_id: str
    description: str
    finding: str
    evidence: str


class ComplianceAndAuditDocumentation(BaseModel):
    nist_ir_phases: list[NistIrPhase] = Field(default_factory=list)
    cri_profile_statements: list[CriDiagnosticStatement] = Field(default_factory=list)
    policy_update_recommendation: str


class InvestigationReport(BaseModel):
    alert_id: str
    triage_assessment: TriageAssessment
    pivot_correlation_timeline: list[PivotTimelineEntry] = Field(default_factory=list)
    remediation_playbook: RemediationPlaybook
    compliance_and_audit_documentation: ComplianceAndAuditDocumentation


class InvestigateRequest(BaseModel):
    alert_id: str
