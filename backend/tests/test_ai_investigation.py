"""Tests for the Tier-3 incident investigation feature.

All Anthropic API calls are mocked.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.correlation.detector import Detector
from app.models.events import Alert, AlertSeverity


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture()
def ransomware_alert() -> Alert:
    return Alert(
        alert_id="inv-alert-001",
        rule="ransomware.known_bad_process",
        severity=AlertSeverity.CRITICAL,
        host="WS-007",
        user="alice",
        source_ip="185.220.101.45",
        detail="known ransomware 'lockbit.exe'",
        mitre_techniques=["T1059.003", "T1490", "T1486"],
    )


# ---------------------------------------------------------------------------
# Mock mode
# ---------------------------------------------------------------------------

def test_investigate_returns_mock_when_no_key(client: TestClient, ransomware_alert: Alert):
    client.app.state.app_state.alerts.append(ransomware_alert)
    os.environ.pop("ANTHROPIC_API_KEY", None)

    with patch.dict("os.environ", {}, clear=True):
        resp = client.post("/ai/investigate", json={"alert_id": "inv-alert-001"})

    assert resp.status_code == 200
    data = resp.json()
    assert "[MOCK]" in data["triage_assessment"]["threat_objectives"]
    assert isinstance(data["pivot_correlation_timeline"], list)
    assert len(data["pivot_correlation_timeline"]) > 0


def test_investigate_404_for_unknown_alert(client: TestClient):
    resp = client.post("/ai/investigate", json={"alert_id": "nope"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Real API call (mocked)
# ---------------------------------------------------------------------------

def test_investigate_calls_claude_and_parses_response(
    client: TestClient, ransomware_alert: Alert,
):
    client.app.state.app_state.alerts.append(ransomware_alert)

    fake = {
        "triage_assessment": {
            "threat_objectives": "Encrypt files for ransom on WS-007.",
            "severity": "CRITICAL",
            "status": "Active",
            "compromised_assets": ["WS-007", "alice"],
        },
        "pivot_correlation_timeline": [
            {
                "timestamp": "2025-06-19T10:00:00Z",
                "source_environment": "LOGON",
                "asset_or_identity": "alice",
                "activity_or_artifact": "Interactive logon",
                "correlation_pivot_point": "logon_id=0x12345",
            },
        ],
        "remediation_playbook": {
            "automated_actions": [
                {
                    "action": "isolate_host",
                    "activity_name": "Isolate WS-007",
                    "params": {"host": "WS-007"},
                    "confidence_score": 0.97,
                    "rationale": "Confirmed ransomware execution.",
                },
            ],
            "analyst_validated_actions": [
                {
                    "action": "review_backups",
                    "priority": "HIGH",
                    "confidence_score": 0.75,
                    "rationale": "Confirm clean backups before recovery.",
                },
            ],
        },
        "compliance_and_audit_documentation": {
            "nist_ir_phases": [
                {"phase": "Detection & Analysis", "activities": ["SIEM fired"], "status": "Complete"},
            ],
            "cri_profile_statements": [
                {"control_id": "DE.AE-2", "description": "Analyze events.", "finding": "Satisfied", "evidence": "ok"},
            ],
            "policy_update_recommendation": "Add detection for variant X.",
        },
    }

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(fake))]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    with patch("app.ai.client._client", mock_client), \
         patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
        resp = client.post("/ai/investigate", json={"alert_id": "inv-alert-001"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["triage_assessment"]["severity"] == "CRITICAL"
    assert data["remediation_playbook"]["automated_actions"][0]["confidence_score"] == 0.97


def test_compliance_section_has_required_fields(client: TestClient, ransomware_alert: Alert):
    client.app.state.app_state.alerts.append(ransomware_alert)
    os.environ.pop("ANTHROPIC_API_KEY", None)
    with patch.dict("os.environ", {}, clear=True):
        resp = client.post("/ai/investigate", json={"alert_id": "inv-alert-001"})
    data = resp.json()
    comp = data["compliance_and_audit_documentation"]
    assert "nist_ir_phases" in comp
    assert "cri_profile_statements" in comp
    assert "policy_update_recommendation" in comp
    assert len(comp["cri_profile_statements"]) > 0


# ---------------------------------------------------------------------------
# Model & detector
# ---------------------------------------------------------------------------

def test_alert_has_mitre_techniques_field():
    a = Alert(alert_id="x", rule="auth.brute_force", severity=AlertSeverity.HIGH, host="DC-01")
    assert a.mitre_techniques == []

    b = Alert(
        alert_id="y", rule="ransomware.known_bad_process",
        severity=AlertSeverity.CRITICAL, host="WS-1",
        mitre_techniques=["T1486"],
    )
    assert b.mitre_techniques == ["T1486"]
    assert b.model_dump()["mitre_techniques"] == ["T1486"]


def test_detector_tags_mitre_techniques(client: TestClient):
    state = client.app.state.app_state
    # Inject a ransomware scenario then run detection.
    client.post("/simulate?scenario=ransomware")
    resp = client.post("/detect")
    assert resp.status_code == 200

    ransom_alerts = [a for a in state.alerts if a.rule == "ransomware.known_bad_process"]
    assert ransom_alerts, "expected at least one ransomware alert"
    assert "T1486" in ransom_alerts[0].mitre_techniques
