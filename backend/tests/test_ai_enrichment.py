"""Tests for the AI enrichment feature.

All Anthropic API calls are mocked — these tests verify the enrichment
logic, prompt construction, and HTTP endpoint behaviour without a real key.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.models.events import Alert, AlertSeverity


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture()
def ransomware_alert() -> Alert:
    return Alert(
        alert_id="test-alert-001",
        rule="ransomware.known_bad_process",
        severity=AlertSeverity.CRITICAL,
        host="WS-007",
        user="alice",
        source_ip="185.220.101.45",
        detail="known ransomware 'lockbit.exe'",
    )


# ---------------------------------------------------------------------------
# Mock mode (no API key)
# ---------------------------------------------------------------------------

def test_enrich_returns_mock_when_no_key(client: TestClient, ransomware_alert: Alert):
    """When ANTHROPIC_API_KEY is absent, enrichment returns clearly-labeled mock data."""
    # Seed the app state with a real alert so the endpoint can find it
    app_state = client.app.state.app_state
    app_state.alerts.append(ransomware_alert)

    with patch.dict("os.environ", {}, clear=True):
        # Remove key if present
        import os
        os.environ.pop("ANTHROPIC_API_KEY", None)

        resp = client.post("/ai/enrich", json={"alert_id": "test-alert-001"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["alert_id"] == "test-alert-001"
    assert "[MOCK]" in data["explanation"]
    assert isinstance(data["recommended_actions"], list)
    assert len(data["recommended_actions"]) > 0
    assert data["confidence"] == 0.0


def test_enrich_404_for_unknown_alert(client: TestClient):
    resp = client.post("/ai/enrich", json={"alert_id": "does-not-exist"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Real API call (mocked Anthropic client)
# ---------------------------------------------------------------------------

def test_enrich_calls_claude_and_parses_response(client: TestClient, ransomware_alert: Alert):
    """When an API key is present, enrichment calls Claude and parses structured JSON."""
    app_state = client.app.state.app_state
    app_state.alerts.append(ransomware_alert)

    fake_response_json = {
        "explanation": "A known ransomware binary was executed on WS-007.",
        "severity_justification": "CRITICAL because an active ransomware process was confirmed.",
        "recommended_actions": ["Isolate WS-007", "Terminate the process", "Check for encryption"],
        "threat_intel": "LockBit is a ransomware-as-a-service operation active since 2019.",
        "confidence": 0.95,
    }

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(fake_response_json))]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    with patch("app.ai.client._client", mock_client), \
         patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
        resp = client.post("/ai/enrich", json={"alert_id": "test-alert-001"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["explanation"] == fake_response_json["explanation"]
    assert data["confidence"] == 0.95
    assert data["recommended_actions"] == fake_response_json["recommended_actions"]


def test_enrich_writes_back_to_alert_object(client: TestClient, ransomware_alert: Alert):
    """After enrichment, the alert object in state has ai_* fields populated."""
    app_state = client.app.state.app_state
    app_state.alerts.append(ransomware_alert)

    import os
    os.environ.pop("ANTHROPIC_API_KEY", None)

    with patch.dict("os.environ", {}, clear=True):
        client.post("/ai/enrich", json={"alert_id": "test-alert-001"})

    alert = next(a for a in app_state.alerts if a.alert_id == "test-alert-001")
    assert alert.ai_explanation is not None
    assert "[MOCK]" in alert.ai_explanation
    assert alert.ai_recommended_actions is not None


def test_alert_model_has_ai_fields():
    """Alert model includes optional ai_* fields that default to None."""
    alert = Alert(
        alert_id="x",
        rule="auth.brute_force",
        severity=AlertSeverity.HIGH,
        host="DC-01",
    )
    assert alert.ai_explanation is None
    assert alert.ai_severity_justification is None
    assert alert.ai_recommended_actions is None
    assert alert.ai_threat_intel is None

    # Fields should appear in model_dump output
    d = alert.model_dump()
    assert "ai_explanation" in d
    assert d["ai_explanation"] is None


# ---------------------------------------------------------------------------
# Future phase stubs return 501
# ---------------------------------------------------------------------------

def test_anomalies_stub_returns_501(client: TestClient):
    resp = client.post("/ai/anomalies")
    assert resp.status_code == 501


def test_nl_query_stub_returns_501(client: TestClient):
    resp = client.post("/ai/query")
    assert resp.status_code == 501
