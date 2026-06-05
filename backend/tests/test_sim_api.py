"""End-to-end test of the simulate -> detect HTTP flow."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.main import create_app


def test_simulate_then_detect_ransomware():
    client = TestClient(create_app(ttl_days=None))
    r = client.post("/simulate", params={"scenario": "ransomware", "difficulty": 1, "seed": 7})
    assert r.status_code == 200
    assert r.json()["injected"] > 0

    r = client.post("/detect")
    rules = {a["rule"] for a in r.json()["new_alerts"]}
    assert "ransomware.known_bad_process" in rules

    # Detection is idempotent across HTTP calls too.
    assert client.post("/detect").json()["new_alerts"] == []
    assert len(client.get("/query/alerts").json()) >= 1
