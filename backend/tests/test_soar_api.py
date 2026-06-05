"""Full pipeline test: simulate -> detect -> respond -> verify containment."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.main import create_app


def test_full_pipeline_ransomware_containment():
    client = TestClient(create_app(ttl_days=None))

    # 1. Inject a ransomware scenario.
    assert client.post("/simulate", params={"scenario": "ransomware", "seed": 11}).status_code == 200
    # 2. Detect.
    new = client.post("/detect").json()["new_alerts"]
    assert any(a["rule"] == "ransomware.known_bad_process" for a in new)
    # 3. Respond: launch playbooks.
    launched = client.post("/soar/respond").json()["launched"]
    assert any(l["playbook"] == "ransomware_containment" for l in launched)
    # 4. Verify the environment was actually contained.
    env = client.get("/soar/environment").json()
    assert len(env["isolated_hosts"]) >= 1
    assert len(env["blocked_ips"]) >= 1
    # 5. Runs are recorded and completed.
    runs = client.get("/soar/runs").json()
    assert all(r["status"] == "COMPLETED" for r in runs)
    assert runs

    # 6. Responding again is idempotent (no new runs).
    assert client.post("/soar/respond").json()["launched"] == []


def test_run_detail_contains_event_history():
    client = TestClient(create_app(ttl_days=None))
    client.post("/simulate", params={"scenario": "brute_force", "seed": 12})
    client.post("/detect")
    launched = client.post("/soar/respond").json()["launched"]
    run_id = launched[0]["run_id"]
    detail = client.get(f"/soar/runs/{run_id}").json()
    types = [e["type"] for e in detail["events"]]
    assert "WORKFLOW_STARTED" in types
    assert "WORKFLOW_COMPLETED" in types
