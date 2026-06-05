"""Tests for the simulation engine and the correlation/detection rules."""

from __future__ import annotations

from app.correlation import Detector
from app.simulation import Difficulty, Scenario, SimulationEngine
from app.state import AppState


def _ingest_all(state: AppState, envelopes):
    for env in envelopes:
        state.ingest(env)


def test_benign_scenario_raises_no_alerts():
    state = AppState()
    eng = SimulationEngine(seed=1)
    _ingest_all(state, eng.build_scenario(Scenario.BENIGN, Difficulty.MEDIUM, base_ts=1_000_000))
    assert Detector(state).run() == []


def test_ransomware_scenario_raises_critical_alert():
    state = AppState()
    eng = SimulationEngine(seed=2)
    _ingest_all(state, eng.build_scenario(Scenario.RANSOMWARE, Difficulty.EASY, base_ts=1_000_000))
    alerts = Detector(state).run()
    rules = {a.rule for a in alerts}
    assert "ransomware.known_bad_process" in rules
    assert "net.c2_beacon" in rules
    ransom = next(a for a in alerts if a.rule == "ransomware.known_bad_process")
    # Correlation must have recovered the source IP from the linked 4624 session.
    assert ransom.source_ip != ""
    assert ransom.severity == 4  # CRITICAL


def test_brute_force_scenario_raises_high_alert():
    state = AppState()
    eng = SimulationEngine(seed=3)
    _ingest_all(state, eng.build_scenario(Scenario.BRUTE_FORCE, Difficulty.EASY, base_ts=1_000_000))
    alerts = Detector(state).run()
    bf = [a for a in alerts if a.rule == "auth.brute_force"]
    assert len(bf) == 1
    assert bf[0].source_ip == "203.0.113.66"


def test_detection_is_idempotent():
    state = AppState()
    eng = SimulationEngine(seed=4)
    _ingest_all(state, eng.build_scenario(Scenario.RANSOMWARE, Difficulty.EASY, base_ts=1_000_000))
    det = Detector(state)
    first = det.run()
    second = det.run()  # re-scan over identical data
    assert len(first) > 0
    assert second == []  # no duplicates
    assert len(state.alerts) == len(first)


def test_logon_process_correlation_join():
    """A 4688 and its 4624 share logon_id -> we can recover who ran what."""
    state = AppState()
    eng = SimulationEngine(seed=5)
    _ingest_all(state, eng.ransomware(base_ts=2_000_000))
    det = Detector(state)
    det.run()
    ransom = next(a for a in state.alerts if a.rule == "ransomware.known_bad_process")
    assert ransom.user == "svc_backup"
    assert ransom.source_ip in {"185.220.101.45", "45.135.232.17", "194.165.16.78"}


def test_internal_traffic_not_flagged_as_brute_force():
    """High logon volume from an internal IP must NOT trip the external brute-force rule."""
    state = AppState()
    eng = SimulationEngine(seed=6)
    # 40 benign logons (internal/empty source IPs) should not exceed external thresholds.
    base = 3_000_000
    for i in range(40):
        state.ingest(eng.benign_logon(base + i))
    alerts = [a for a in Detector(state).run() if a.rule == "auth.brute_force"]
    assert alerts == []
