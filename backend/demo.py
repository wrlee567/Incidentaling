"""End-to-end, in-process demo of the SIEM/SOAR pipeline (no server required).

Run from the backend/ directory:  python demo.py
"""

from __future__ import annotations

from app.correlation import Detector
from app.playbooks import playbook_for_alert
from app.simulation import Difficulty, Scenario, SimulationEngine
from app.state import AppState


def banner(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def run_scenario(scenario: Scenario) -> None:
    banner(f"SCENARIO: {scenario.value}")
    state = AppState()
    detector = Detector(state)

    # 1. EDR telemetry streams in (push for critical, spool for routine).
    engine = SimulationEngine(seed=42)
    envelopes = engine.build_scenario(scenario, Difficulty.MEDIUM)
    for env in envelopes:
        state.ingest(env)
    print(f"Ingested {len(envelopes)} telemetry events.")
    for kind, tbl in state.tables.items():
        print(f"  {kind.value:8s}: {tbl.row_count:3d} rows, "
              f"{sum(tbl.memory_footprint().values())} bytes")

    # 2. SIEM correlation raises alerts.
    alerts = detector.run()
    print(f"\nSIEM raised {len(alerts)} alert(s):")
    for a in alerts:
        print(f"  [{a.severity.name:8s}] {a.rule:30s} host={a.host} -> {a.detail}")

    # 3. SOAR responds with playbooks.
    print("\nSOAR response:")
    for a in alerts:
        wf = playbook_for_alert(a)
        if wf is None:
            continue
        run_id = state.engine.start(wf, trigger={"alert_id": a.alert_id})
        status = state.history.get_run(run_id)["status"]
        print(f"  alert {a.rule} -> playbook '{wf.name}' [{status}]")

    # 4. Resulting containment state.
    env = state.environment
    print("\nContainment actions taken:")
    for label, items in [
        ("isolated hosts", env.isolated_hosts),
        ("blocked IPs", env.blocked_ips),
        ("locked accounts", env.locked_accounts),
        ("MFA enforced", env.mfa_enforced),
    ]:
        if items:
            print(f"  {label}: {sorted(items)}")


if __name__ == "__main__":
    for sc in (Scenario.BENIGN, Scenario.BRUTE_FORCE, Scenario.RANSOMWARE):
        run_scenario(sc)
    print()
