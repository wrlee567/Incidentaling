"""The simulated enterprise environment that SOAR activities act upon.

Every activity here is **idempotent**: applying it twice leaves the environment in the
same observable state as applying it once. This is the contract that makes at-least-once
worker execution safe. A worker can update a firewall rule, crash before acknowledging,
get retried, and re-apply the rule — with no compounding side effects — because the
underlying operation is a set membership change, not an append.

``actions`` records every invocation (including retries) purely for observability; the
*state* sets are what idempotency is asserted against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.models import now_ms


@dataclass
class SimulatedEnvironment:
    isolated_hosts: set[str] = field(default_factory=set)
    terminated_on: set[str] = field(default_factory=set)
    blocked_ips: set[str] = field(default_factory=set)
    segregated_subnets: set[str] = field(default_factory=set)
    locked_accounts: set[str] = field(default_factory=set)
    password_resets: set[str] = field(default_factory=set)
    mfa_enforced: set[str] = field(default_factory=set)
    exfil_reviews: dict[str, str] = field(default_factory=dict)
    # Append-only call log; length reflects retries, state sets do not.
    actions: list[str] = field(default_factory=list)


# An activity: (env, params) -> result dict. Must be idempotent.
Activity = Callable[[SimulatedEnvironment, dict], dict]


def isolate_endpoint(env: SimulatedEnvironment, p: dict) -> dict:
    host = p["host"]
    env.actions.append(f"isolate_endpoint({host})")
    env.isolated_hosts.add(host)
    return {"isolated": host}


def terminate_malicious_processes(env: SimulatedEnvironment, p: dict) -> dict:
    host = p["host"]
    env.actions.append(f"terminate_malicious_processes({host})")
    env.terminated_on.add(host)
    return {"terminated_on": host}


def block_c2(env: SimulatedEnvironment, p: dict) -> dict:
    ip = p["ip"]
    env.actions.append(f"block_c2({ip})")
    env.blocked_ips.add(ip)
    return {"blocked": ip}


def block_ip(env: SimulatedEnvironment, p: dict) -> dict:
    ip = p["ip"]
    env.actions.append(f"block_ip({ip})")
    env.blocked_ips.add(ip)
    return {"blocked": ip}


def segregate_critical_systems(env: SimulatedEnvironment, p: dict) -> dict:
    subnet = p["subnet"]
    env.actions.append(f"segregate_critical_systems({subnet})")
    env.segregated_subnets.add(subnet)
    return {"segregated": subnet}


def lock_account(env: SimulatedEnvironment, p: dict) -> dict:
    user = p["user"]
    env.actions.append(f"lock_account({user})")
    env.locked_accounts.add(user)
    return {"locked": user}


def force_password_reset(env: SimulatedEnvironment, p: dict) -> dict:
    user = p["user"]
    env.actions.append(f"force_password_reset({user})")
    env.password_resets.add(user)
    return {"reset": user}


def enforce_mfa(env: SimulatedEnvironment, p: dict) -> dict:
    user = p["user"]
    env.actions.append(f"enforce_mfa({user})")
    env.mfa_enforced.add(user)
    return {"mfa": user}


def review_exfiltration(env: SimulatedEnvironment, p: dict) -> dict:
    host = p["host"]
    env.actions.append(f"review_exfiltration({host})")
    finding = "no_exfiltration_detected"
    env.exfil_reviews[host] = finding
    return {"host": host, "finding": finding}


def compute_time_to_contain(env: SimulatedEnvironment, p: dict) -> dict:
    """Compute elapsed ms between detection and containment completion."""
    detected_ts = int(p.get("detected_ts", 0))
    elapsed = max(0, now_ms() - detected_ts) if detected_ts else 0
    env.actions.append(f"compute_time_to_contain({elapsed}ms)")
    return {"time_to_contain_ms": elapsed}


ACTIVITY_REGISTRY: dict[str, Activity] = {
    "isolate_endpoint": isolate_endpoint,
    "terminate_malicious_processes": terminate_malicious_processes,
    "block_c2": block_c2,
    "block_ip": block_ip,
    "segregate_critical_systems": segregate_critical_systems,
    "lock_account": lock_account,
    "force_password_reset": force_password_reset,
    "enforce_mfa": enforce_mfa,
    "review_exfiltration": review_exfiltration,
    "compute_time_to_contain": compute_time_to_contain,
}
