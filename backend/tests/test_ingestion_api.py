"""Tests for the hybrid push/pull ingestion API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.models import AlertSeverity, TelemetryKind


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(ttl_days=None))


def _logon(severity: int = 0) -> dict:
    return {
        "kind": TelemetryKind.LOGON.value,
        "severity": severity,
        "payload": {"host": "ws1", "user": "alice", "logon_id": "0x3e7", "ts": 1000},
    }


def test_health(client: TestClient):
    assert client.get("/health").json()["status"] == "ok"


def test_push_accepts_high_severity(client: TestClient):
    r = client.post("/ingest/push", json=_logon(severity=AlertSeverity.CRITICAL))
    assert r.status_code == 200
    assert r.json() == {"accepted": 1, "transport": "push"}
    assert client.get("/query/stats").json()["logon"]["rows"] == 1


def test_push_rejects_routine_severity(client: TestClient):
    r = client.post("/ingest/push", json=_logon(severity=AlertSeverity.LOW))
    assert r.status_code == 400
    assert client.get("/query/stats").json()["logon"]["rows"] == 0


def test_push_rejects_malformed_payload(client: TestClient):
    bad = {"kind": "logon", "severity": 4, "payload": {"host": "ws1"}}  # missing logon_id
    r = client.post("/ingest/push", json=bad)
    assert r.status_code == 422


def test_spool_then_pull_roundtrip(client: TestClient):
    # Routine telemetry goes to the spool and is NOT yet in the store.
    for i in range(5):
        r = client.post("/ingest/spool", json=_logon(severity=AlertSeverity.INFO))
        assert r.json()["spooled"] is True
    assert client.get("/query/stats").json()["logon"]["rows"] == 0

    # The server pulls a batch -> now persisted.
    r = client.post("/ingest/pull", params={"max_batch": 3})
    assert r.json() == {"accepted": 3, "transport": "pull"}
    assert client.get("/query/stats").json()["logon"]["rows"] == 3

    # Drain the rest.
    r = client.post("/ingest/pull", params={"max_batch": 100})
    assert r.json()["accepted"] == 2
    assert client.get("/query/stats").json()["logon"]["rows"] == 5


def test_query_events_endpoint(client: TestClient):
    client.post("/ingest/push", json=_logon(severity=AlertSeverity.CRITICAL))
    rows = client.get("/query/events/logon").json()
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    assert rows[0]["event_id"] == 4624
