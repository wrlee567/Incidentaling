"""AI feature implementations.

Each function in this module calls Claude to produce enriched analysis of
security alerts. When ANTHROPIC_API_KEY is not set, all functions return
clearly-labeled mock data so the app runs fully without a real API key.
"""

from __future__ import annotations

import json
import re

from app.ai.client import MODEL, get_client
from app.models.ai_models import AlertEnrichment
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
