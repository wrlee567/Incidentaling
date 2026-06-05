"""Tests for the DAG model, the durable workflow engine, and the playbooks."""

from __future__ import annotations

import pytest

from app.models import Alert, AlertSeverity
from app.orchestration import (
    CrashError,
    EventHistory,
    SimulatedEnvironment,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStep,
)
from app.playbooks import build_playbook, playbook_for_alert


# -- DAG validation -----------------------------------------------------------

def test_dag_rejects_duplicate_ids():
    with pytest.raises(Exception):
        WorkflowDefinition(name="x", steps=[
            WorkflowStep(id="a", activity="isolate_endpoint"),
            WorkflowStep(id="a", activity="block_ip"),
        ])


def test_dag_rejects_unknown_dependency():
    with pytest.raises(Exception):
        WorkflowDefinition(name="x", steps=[
            WorkflowStep(id="a", activity="isolate_endpoint", depends_on=["ghost"]),
        ])


def test_dag_rejects_cycle():
    with pytest.raises(Exception):
        WorkflowDefinition(name="x", steps=[
            WorkflowStep(id="a", activity="isolate_endpoint", depends_on=["b"]),
            WorkflowStep(id="b", activity="block_ip", depends_on=["a"]),
        ])


def test_ready_steps_respects_dependencies():
    wf = build_playbook("ransomware", _ransom_alert())
    assert wf.ready_steps(set()) == ["isolate"]
    assert set(wf.ready_steps({"isolate"})) == {"terminate", "block_c2", "segregate"}
    assert wf.ready_steps({"isolate", "terminate", "block_c2", "segregate"}) == ["ttc"]


# -- engine happy path --------------------------------------------------------

def _ransom_alert() -> Alert:
    return Alert(
        alert_id="a1", rule="ransomware.known_bad_process", severity=AlertSeverity.CRITICAL,
        host="FILE-01", source_ip="185.220.101.45", ts=1,
    )


def _bf_alert() -> Alert:
    return Alert(
        alert_id="a2", rule="auth.brute_force", severity=AlertSeverity.HIGH,
        host="DC-01", user="admin", source_ip="203.0.113.66", ts=1,
    )


def test_ransomware_playbook_runs_to_completion():
    history, env = EventHistory(), SimulatedEnvironment()
    engine = WorkflowEngine(history, env)
    wf = build_playbook("ransomware", _ransom_alert())
    run_id = engine.start(wf, trigger={"alert_id": "a1"})

    assert env.isolated_hosts == {"FILE-01"}
    assert env.terminated_on == {"FILE-01"}
    assert env.blocked_ips == {"185.220.101.45"}
    assert env.segregated_subnets == {"10.0.0.0/24"}
    assert history.get_run(run_id)["status"] == "COMPLETED"
    # All five steps completed exactly once.
    assert history.completed_steps(run_id) == {"isolate", "terminate", "block_c2", "segregate", "ttc"}
    assert all(c == 1 for c in history.attempt_counts(run_id).values())


def test_brute_force_playbook_runs_to_completion():
    history, env = EventHistory(), SimulatedEnvironment()
    WorkflowEngine(history, env).start(build_playbook("brute_force", _bf_alert()), trigger={})
    assert env.locked_accounts == {"admin"}
    assert env.blocked_ips == {"203.0.113.66"}
    assert env.password_resets == {"admin"}
    assert env.mfa_enforced == {"admin"}
    assert env.exfil_reviews == {"DC-01": "no_exfiltration_detected"}


# -- durability & idempotency -------------------------------------------------

def test_crash_then_resume_is_idempotent():
    """A worker crashes after 'terminate' side effect but before its ack; a replacement
    engine resumes from durable history and the world ends in one consistent state."""
    history, env = EventHistory(), SimulatedEnvironment()

    crashed = {"done": False}

    def fault(step_id: str, attempt: int) -> None:
        if step_id == "terminate" and attempt == 1 and not crashed["done"]:
            crashed["done"] = True
            raise CrashError("worker died before ack")

    engine1 = WorkflowEngine(history, env, fault_injector=fault)
    wf = build_playbook("ransomware", _ransom_alert())
    with pytest.raises(CrashError):
        engine1.start(wf, trigger={})

    # Find the run that was started, then resume with a fresh, fault-free engine.
    run_id = history.conn.execute("SELECT run_id FROM workflow_runs LIMIT 1").fetchone()["run_id"]

    engine2 = WorkflowEngine(history, env)  # the "replacement worker"
    engine2.resume(run_id)

    # Despite 'terminate' running twice, idempotent activities yield one final state.
    assert env.terminated_on == {"FILE-01"}
    assert history.attempt_counts(run_id)["terminate"] == 2
    assert history.attempt_counts(run_id)["isolate"] == 1
    assert history.get_run(run_id)["status"] == "COMPLETED"
    assert history.completed_steps(run_id) == {"isolate", "terminate", "block_c2", "segregate", "ttc"}


def test_time_to_contain_recorded():
    history, env = EventHistory(), SimulatedEnvironment()
    engine = WorkflowEngine(history, env)
    run_id = engine.start(build_playbook("ransomware", _ransom_alert()), trigger={})
    result = engine._aggregate_result(run_id)
    assert "time_to_contain_ms" in result["ttc"]
    assert result["ttc"]["time_to_contain_ms"] >= 0


# -- alert -> playbook routing ------------------------------------------------

def test_playbook_for_alert_routing():
    assert playbook_for_alert(_ransom_alert()).name == "ransomware_containment"
    assert playbook_for_alert(_bf_alert()).name == "brute_force_mitigation"
    none_alert = Alert(alert_id="x", rule="unknown.rule", severity=AlertSeverity.LOW, host="h", ts=1)
    assert playbook_for_alert(none_alert) is None
