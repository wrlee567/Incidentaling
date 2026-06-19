"""AI feature implementations.

Each function in this module calls Claude to produce enriched analysis of
security alerts. When ANTHROPIC_API_KEY is not set, all functions return
clearly-labeled mock data so the app runs fully without a real API key.
"""

from __future__ import annotations

import json
import re

from app.ai.client import MODEL, get_client
from app.models.ai_models import (
    AlertEnrichment,
    AnalystValidatedAction,
    AutomatedAction,
    ComplianceAndAuditDocumentation,
    CriDiagnosticStatement,
    InvestigationReport,
    NistIrPhase,
    PivotTimelineEntry,
    RemediationPlaybook,
    TriageAssessment,
)
from app.models.events import Alert, TelemetryKind
from app.state import AppState

_SYSTEM_PROMPT = """\
You are a tier-2 SOC analyst reviewing an automated SIEM alert.
Your job is to provide clear, actionable analysis for the on-call analyst.

You will be given:
- The alert details (rule that fired, severity, host, user, source IP)
- Related telemetry events from the SIEM (logons, process creations, network flows)

Return ONLY a valid JSON object with these exact keys:
- "explanation": plain-English description of what happened (2-3 sentences)
- "severity_justification": why this severity level is appropriate (1-2 sentences)
- "recommended_actions": array of 3-5 specific, ordered actions the analyst should take right now
- "threat_intel": context about this attack pattern, threat actor, or malware family (2-3 sentences)
- "confidence": your confidence in this analysis as a float from 0.0 to 1.0

Do not include markdown, code fences, or any text outside the JSON object.\
"""


def _gather_context(alert: Alert, state: AppState) -> list[dict]:
    """Pull the most relevant telemetry rows to give Claude evidence."""
    rows: list[dict] = []

    if alert.rule == "ransomware.known_bad_process":
        # Get recent process events from the affected host
        rows += state.tables[TelemetryKind.PROCESS].query(
            columns=["ts", "host", "user", "process_name", "command_line"],
            where={"host": alert.host},
            limit=10,
        )
        # Get logon events for the user on that host
        if alert.user:
            rows += state.tables[TelemetryKind.LOGON].query(
                columns=["ts", "host", "user", "source_ip", "auth_package"],
                where={"user": alert.user},
                limit=5,
            )

    elif alert.rule == "auth.brute_force":
        # Get the logon flood from the attacking source IP
        rows += state.tables[TelemetryKind.LOGON].query(
            columns=["ts", "host", "user", "source_ip", "auth_package"],
            where={"source_ip": alert.source_ip},
            limit=20,
        )

    elif alert.rule == "net.c2_beacon":
        # alert.source_ip holds the C2 destination IP for this rule
        rows += state.tables[TelemetryKind.NETFLOW].query(
            columns=["ts", "host", "src_ip", "dst_ip", "bytes_sent", "bytes_recv"],
            where={"dst_ip": alert.source_ip},
            limit=10,
        )
        # Also pull recent process activity from the beaconing host
        rows += state.tables[TelemetryKind.PROCESS].query(
            columns=["ts", "host", "user", "process_name", "command_line"],
            where={"host": alert.host},
            limit=5,
        )

    return rows


def _parse_enrichment_json(alert_id: str, text: str) -> AlertEnrichment:
    """Extract and parse the JSON object from Claude's response."""
    # Strip optional code fences in case Claude wraps the JSON anyway
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    json_str = match.group(1) if match else text.strip()

    data = json.loads(json_str)
    return AlertEnrichment(
        alert_id=alert_id,
        explanation=str(data.get("explanation", "")),
        severity_justification=str(data.get("severity_justification", "")),
        recommended_actions=list(data.get("recommended_actions", [])),
        threat_intel=str(data.get("threat_intel", "")),
        confidence=float(data.get("confidence", 0.5)),
    )


def _mock_enrichment(alert: Alert) -> AlertEnrichment:
    """Return placeholder enrichment used when no API key is configured."""
    rule_summaries = {
        "ransomware.known_bad_process": "a known ransomware binary was executed on the host",
        "auth.brute_force": "a burst of failed logon attempts was detected from an external IP",
        "net.c2_beacon": "network traffic to a known command-and-control server was observed",
    }
    summary = rule_summaries.get(alert.rule, f"detection rule '{alert.rule}' fired")

    return AlertEnrichment(
        alert_id=alert.alert_id,
        explanation=(
            f"[MOCK] The rule '{alert.rule}' fired on host {alert.host!r} — {summary}. "
            "In production, Claude would provide a detailed explanation based on the actual "
            "telemetry evidence. Set ANTHROPIC_API_KEY to enable real AI analysis."
        ),
        severity_justification=(
            f"[MOCK] Severity {alert.severity.name} was assigned because the rule "
            f"'{alert.rule}' maps to this severity by default. Claude would justify this "
            "based on the specific evidence in the telemetry."
        ),
        recommended_actions=[
            f"[MOCK] Isolate {alert.host} from the network immediately",
            "[MOCK] Review the full event timeline for this host",
            "[MOCK] Check for lateral movement to adjacent systems",
            "[MOCK] Set ANTHROPIC_API_KEY for real AI-powered recommended actions",
        ],
        threat_intel=(
            "[MOCK] Threat intelligence context would appear here, including known threat "
            "actor TTPs, malware family details, and relevant CVEs. Set ANTHROPIC_API_KEY "
            "to activate real threat intelligence enrichment."
        ),
        confidence=0.0,
    )


async def enrich_alert(alert: Alert, state: AppState) -> AlertEnrichment:
    """Call Claude to produce a structured enrichment for the given alert.

    Returns mock enrichment if ANTHROPIC_API_KEY is not set, so the app
    runs in development without a real key.
    """
    client = get_client()
    if client is None:
        return _mock_enrichment(alert)

    context_rows = _gather_context(alert, state)

    user_message = (
        f"Alert:\n{json.dumps(alert.model_dump(exclude={'ai_explanation', 'ai_severity_justification', 'ai_recommended_actions', 'ai_threat_intel'}), indent=2)}\n\n"
        f"Related telemetry ({len(context_rows)} events):\n"
        f"{json.dumps(context_rows, indent=2, default=str)}"
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text
    return _parse_enrichment_json(alert.alert_id, raw)


# ---------------------------------------------------------------------------
# Tier-3 Incident Response investigation
# ---------------------------------------------------------------------------

_TIER3_SYSTEM_PROMPT = """\
You are a Tier-3 Incident Response analyst conducting a full investigation of a
correlated SIEM alert. You receive the alert plus three telemetry datasets from
the columnar store (logon events, process creations, network flows) for the
affected host.

Your responsibilities:
1. Parse and normalize all three telemetry sources.
2. Cross-pivot across them using `logon_id`, `host`, `user`, and IP fields to
   reconstruct the attacker's path (initial access -> execution -> impact).
3. Map each attacker action you identify to a MITRE ATT&CK technique ID.
4. Produce a containment playbook split by confidence:
   - confidence_score >= 0.90 -> "automated_actions" (will execute via SOAR)
   - confidence_score <  0.90 -> "analyst_validated_actions" (requires human)
5. Produce compliance documentation aligned to:
   - NIST SP 800-61r3 phases (Preparation, Detection & Analysis, Containment,
     Eradication & Recovery, Post-Incident Activity)
   - NIST CSF v2 function families
   - CRI Profile v2.2 controls — include at minimum diagnostic statements for
     DE.AE-2, RS.RP-1, PR.DS-1, RS.CO-2, RC.RP-1

Return ONLY a valid JSON object with exactly these top-level keys:
- "triage_assessment": { "threat_objectives": str, "severity": str,
    "status": str, "compromised_assets": [str, ...] }
- "pivot_correlation_timeline": [ { "timestamp": str, "source_environment": str,
    "asset_or_identity": str, "activity_or_artifact": str,
    "correlation_pivot_point": str }, ... ]
- "remediation_playbook": {
    "automated_actions": [ { "action": str, "activity_name": str,
        "params": object, "confidence_score": float >= 0.90,
        "rationale": str }, ... ],
    "analyst_validated_actions": [ { "action": str, "priority": str,
        "confidence_score": float < 0.90, "rationale": str }, ... ]
  }
- "compliance_and_audit_documentation": {
    "nist_ir_phases": [ { "phase": str, "activities": [str, ...],
        "status": str }, ... ],
    "cri_profile_statements": [ { "control_id": str, "description": str,
        "finding": str, "evidence": str }, ... ],
    "policy_update_recommendation": str
  }

Do not include markdown, code fences, or any text outside the JSON object.\
"""


def _gather_full_context(alert: Alert, state: AppState) -> dict[str, list[dict]]:
    """Pull all three telemetry sources for the alert's host (and pivot IPs)."""
    logon_rows = state.tables[TelemetryKind.LOGON].query(
        columns=["ts", "host", "user", "source_ip", "auth_package", "logon_id"],
        where={"host": alert.host},
        limit=20,
    )
    if alert.source_ip:
        logon_rows += state.tables[TelemetryKind.LOGON].query(
            columns=["ts", "host", "user", "source_ip", "auth_package", "logon_id"],
            where={"source_ip": alert.source_ip},
            limit=20,
        )

    process_rows = state.tables[TelemetryKind.PROCESS].query(
        columns=["ts", "host", "user", "process_name", "command_line", "logon_id"],
        where={"host": alert.host},
        limit=20,
    )

    netflow_rows = state.tables[TelemetryKind.NETFLOW].query(
        columns=["ts", "host", "src_ip", "dst_ip", "src_port", "dst_port", "bytes_sent", "bytes_recv"],
        where={"host": alert.host},
        limit=20,
    )
    if alert.source_ip:
        netflow_rows += state.tables[TelemetryKind.NETFLOW].query(
            columns=["ts", "host", "src_ip", "dst_ip", "src_port", "dst_port", "bytes_sent", "bytes_recv"],
            where={"dst_ip": alert.source_ip},
            limit=20,
        )

    return {
        "logon_events": logon_rows,
        "process_events": process_rows,
        "netflow_events": netflow_rows,
    }


def _parse_investigation_json(alert_id: str, text: str) -> InvestigationReport:
    """Extract and parse the JSON object from Claude's tier-3 response."""
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    json_str = match.group(1) if match else text.strip()
    data = json.loads(json_str)
    return InvestigationReport(alert_id=alert_id, **data)


def _mock_investigation(alert: Alert) -> InvestigationReport:
    """Return placeholder investigation when no API key is configured."""
    return InvestigationReport(
        alert_id=alert.alert_id,
        triage_assessment=TriageAssessment(
            threat_objectives=(
                f"[MOCK] The rule '{alert.rule}' fired on host {alert.host!r}. "
                "Claude would describe the attacker's apparent objectives based on "
                "the telemetry chain. Set ANTHROPIC_API_KEY for real analysis."
            ),
            severity="[MOCK] CRITICAL",
            status="[MOCK] Active",
            compromised_assets=[alert.host] + ([alert.user] if alert.user else []),
        ),
        pivot_correlation_timeline=[
            PivotTimelineEntry(
                timestamp="[MOCK] 2025-01-01T00:00:00Z",
                source_environment="LOGON",
                asset_or_identity=alert.user or alert.host,
                activity_or_artifact="[MOCK] Initial access logon observed",
                correlation_pivot_point=f"logon_id -> {alert.host}",
            ),
            PivotTimelineEntry(
                timestamp="[MOCK] 2025-01-01T00:05:00Z",
                source_environment="PROCESS",
                asset_or_identity=alert.host,
                activity_or_artifact="[MOCK] Suspicious process execution",
                correlation_pivot_point=f"host={alert.host}",
            ),
            PivotTimelineEntry(
                timestamp="[MOCK] 2025-01-01T00:10:00Z",
                source_environment="NETFLOW",
                asset_or_identity=alert.host,
                activity_or_artifact="[MOCK] Outbound beacon observed",
                correlation_pivot_point=f"src_ip -> {alert.source_ip or 'external'}",
            ),
        ],
        remediation_playbook=RemediationPlaybook(
            automated_actions=[
                AutomatedAction(
                    action="isolate_host",
                    activity_name=f"[MOCK] Isolate {alert.host}",
                    params={"host": alert.host},
                    confidence_score=0.97,
                    rationale="[MOCK] High-confidence containment for confirmed compromise.",
                ),
            ],
            analyst_validated_actions=[
                AnalystValidatedAction(
                    action="reset_credentials",
                    priority="HIGH",
                    confidence_score=0.7,
                    rationale="[MOCK] User credential reset recommended; analyst should confirm scope.",
                ),
            ],
        ),
        compliance_and_audit_documentation=ComplianceAndAuditDocumentation(
            nist_ir_phases=[
                NistIrPhase(
                    phase="Detection & Analysis",
                    activities=["[MOCK] SIEM correlation fired", "[MOCK] Tier-3 review initiated"],
                    status="In Progress",
                ),
                NistIrPhase(
                    phase="Containment, Eradication & Recovery",
                    activities=["[MOCK] Host isolation queued"],
                    status="Pending",
                ),
            ],
            cri_profile_statements=[
                CriDiagnosticStatement(
                    control_id="DE.AE-2",
                    description="Detected events are analyzed to understand attack targets and methods.",
                    finding="Partially Satisfied",
                    evidence=f"[MOCK] Alert {alert.alert_id} triaged by Tier-3.",
                ),
                CriDiagnosticStatement(
                    control_id="RS.RP-1",
                    description="Response plan is executed during or after an incident.",
                    finding="Satisfied",
                    evidence="[MOCK] SOAR playbook engaged.",
                ),
                CriDiagnosticStatement(
                    control_id="PR.DS-1",
                    description="Data-at-rest is protected.",
                    finding="Partially Satisfied",
                    evidence="[MOCK] Encryption status pending verification.",
                ),
                CriDiagnosticStatement(
                    control_id="RS.CO-2",
                    description="Incidents are reported consistent with established criteria.",
                    finding="Satisfied",
                    evidence="[MOCK] Incident logged in this investigation report.",
                ),
                CriDiagnosticStatement(
                    control_id="RC.RP-1",
                    description="Recovery plan is executed during or after a cybersecurity incident.",
                    finding="Not Satisfied",
                    evidence="[MOCK] Recovery has not begun.",
                ),
            ],
            policy_update_recommendation=(
                "[MOCK] Review detection coverage and update the incident response "
                "runbook with the techniques observed. Set ANTHROPIC_API_KEY for "
                "real policy recommendations."
            ),
        ),
    )


async def investigate_incident(alert: Alert, state: AppState) -> InvestigationReport:
    """Call Claude to produce a full Tier-3 investigation report.

    Returns mock data when ANTHROPIC_API_KEY is not set.
    """
    client = get_client()
    if client is None:
        return _mock_investigation(alert)

    full_context = _gather_full_context(alert, state)

    alert_dump = alert.model_dump(
        exclude={
            "ai_explanation",
            "ai_severity_justification",
            "ai_recommended_actions",
            "ai_threat_intel",
        }
    )

    user_message = (
        f"Alert:\n{json.dumps(alert_dump, indent=2)}\n\n"
        f"MITRE techniques tagged at detection: {alert.mitre_techniques}\n\n"
        f"Logon events ({len(full_context['logon_events'])}):\n"
        f"{json.dumps(full_context['logon_events'], indent=2, default=str)}\n\n"
        f"Process events ({len(full_context['process_events'])}):\n"
        f"{json.dumps(full_context['process_events'], indent=2, default=str)}\n\n"
        f"NetFlow events ({len(full_context['netflow_events'])}):\n"
        f"{json.dumps(full_context['netflow_events'], indent=2, default=str)}"
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=_TIER3_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text
    return _parse_investigation_json(alert.alert_id, raw)


async def auto_enrich(alert: Alert, state: AppState) -> None:
    """Enrich an alert in the background and write results back to the alert object.

    Called as an asyncio background task from the detect endpoint. Failures are
    swallowed so enrichment never disrupts the detection pipeline.
    """
    try:
        enrichment = await enrich_alert(alert, state)
        alert.ai_explanation = enrichment.explanation
        alert.ai_severity_justification = enrichment.severity_justification
        alert.ai_recommended_actions = enrichment.recommended_actions
        alert.ai_threat_intel = enrichment.threat_intel
    except Exception:
        pass  # enrichment is best-effort
