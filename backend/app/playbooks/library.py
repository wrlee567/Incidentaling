"""Concrete incident-response playbooks as DAGs.

Each playbook is parameterized by the :class:`Alert` that triggered it. The DAGs encode
real dependency structure — e.g. you isolate an endpoint *before* terminating processes
and segregating neighbours, and those containment actions run in parallel, converging on
a final time-to-contain measurement.
"""

from __future__ import annotations

from app.models import Alert
from app.orchestration.dag import WorkflowDefinition, WorkflowStep

# Critical subnet the ransomware playbook protects.
CRITICAL_SUBNET = "10.0.0.0/24"


def ransomware_playbook(alert: Alert) -> WorkflowDefinition:
    """Isolate -> (terminate || block C2 || segregate) -> measure time-to-contain."""
    host = alert.host
    c2 = alert.source_ip or "0.0.0.0"
    return WorkflowDefinition(
        name="ransomware_containment",
        steps=[
            WorkflowStep(id="isolate", activity="isolate_endpoint", params={"host": host}),
            WorkflowStep(
                id="terminate", activity="terminate_malicious_processes",
                params={"host": host}, depends_on=["isolate"],
            ),
            WorkflowStep(
                id="block_c2", activity="block_c2", params={"ip": c2}, depends_on=["isolate"],
            ),
            WorkflowStep(
                id="segregate", activity="segregate_critical_systems",
                params={"subnet": CRITICAL_SUBNET}, depends_on=["isolate"],
            ),
            WorkflowStep(
                id="ttc", activity="compute_time_to_contain",
                params={"detected_ts": alert.ts},
                depends_on=["terminate", "block_c2", "segregate"],
            ),
        ],
    )


def brute_force_playbook(alert: Alert) -> WorkflowDefinition:
    """Lock account & block IP -> reset password & review exfil -> enforce MFA."""
    user = alert.user or "unknown"
    ip = alert.source_ip or "0.0.0.0"
    host = alert.host
    return WorkflowDefinition(
        name="brute_force_mitigation",
        steps=[
            WorkflowStep(id="lock", activity="lock_account", params={"user": user}),
            WorkflowStep(id="block_ip", activity="block_ip", params={"ip": ip}),
            WorkflowStep(
                id="reset", activity="force_password_reset",
                params={"user": user}, depends_on=["lock"],
            ),
            WorkflowStep(
                id="exfil", activity="review_exfiltration",
                params={"host": host}, depends_on=["lock", "block_ip"],
            ),
            WorkflowStep(
                id="mfa", activity="enforce_mfa", params={"user": user}, depends_on=["reset"],
            ),
        ],
    )


# Maps detection rule -> playbook builder.
_RULE_TO_PLAYBOOK = {
    "ransomware.known_bad_process": ransomware_playbook,
    "net.c2_beacon": ransomware_playbook,
    "auth.brute_force": brute_force_playbook,
}


def build_playbook(name: str, alert: Alert) -> WorkflowDefinition:
    builders = {"ransomware": ransomware_playbook, "brute_force": brute_force_playbook}
    if name not in builders:
        raise KeyError(f"unknown playbook {name!r}")
    return builders[name](alert)


def playbook_for_alert(alert: Alert) -> WorkflowDefinition | None:
    """Select the playbook a given alert should trigger, or None if none applies."""
    builder = _RULE_TO_PLAYBOOK.get(alert.rule)
    return builder(alert) if builder else None
