"""Generates realistic SOC telemetry to drive the simulator.

The generator produces :class:`TelemetryEnvelope` objects (the same wire format the
ingestion API accepts), so a scenario can be replayed either in-process (feeding an
``AppState`` directly) or over HTTP against a running server.

Authenticity details that matter for detection and forensics:

* 4624 logons set protocol-correct fields — Kerberos network logons omit the
  workstation, NTLM logons omit the source TCP/IP detail.
* A logon and the processes it spawns share a ``logon_id`` so the correlation engine
  can answer "which network identity executed this binary?".
* Attack telemetry is mixed into benign noise so the analyst (or a rule) must find
  the signal.
"""

from __future__ import annotations

import random
import uuid
from enum import IntEnum, StrEnum

from app.models import (
    AlertSeverity,
    LogonType,
    NetFlowEvent,
    ProcessCreationEvent,
    TelemetryEnvelope,
    TelemetryKind,
    now_ms,
)

# Indicators of compromise the correlation engine knows about.
KNOWN_BAD_PROCESSES = {"lockbit.exe", "wannacry.exe", "ryuk.exe", "mimikatz.exe"}
C2_IPS = {"185.220.101.45", "45.135.232.17", "194.165.16.78"}

_HOSTS = [f"WS-{i:03d}" for i in range(1, 31)] + ["DC-01", "FILE-01", "ERP-01"]
_USERS = ["alice", "bob", "carol", "dave", "erin", "svc_backup", "admin"]
_BENIGN_PROCS = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Google\Chrome\chrome.exe",
    r"C:\Windows\System32\cmd.exe",
]
_INTERNAL_NET = "10.0.{}.{}"


class Scenario(StrEnum):
    BENIGN = "benign"
    BRUTE_FORCE = "brute_force"
    RANSOMWARE = "ransomware"


class Difficulty(IntEnum):
    """Higher difficulty buries the attack in more benign noise."""

    EASY = 1
    MEDIUM = 2
    HARD = 3


def _internal_ip(rng: random.Random) -> str:
    return _INTERNAL_NET.format(rng.randint(0, 9), rng.randint(2, 254))


class SimulationEngine:
    """Builds telemetry batches for scenarios at a chosen difficulty."""

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    # -- primitives ------------------------------------------------------------

    def benign_logon(self, ts: int) -> TelemetryEnvelope:
        rng = self.rng
        kerberos = rng.random() < 0.5
        logon_id = f"0x{rng.randint(0x10000, 0xFFFFFF):x}"
        return TelemetryEnvelope(
            kind=TelemetryKind.LOGON,
            severity=AlertSeverity.INFO,
            payload={
                "ts": ts,
                "host": rng.choice(_HOSTS),
                "user": rng.choice(_USERS),
                "logon_type": LogonType.NETWORK if kerberos else LogonType.INTERACTIVE,
                "logon_process": "Kerberos" if kerberos else "User32",
                "auth_package": "Kerberos" if kerberos else "NTLM",
                # Kerberos network logons omit workstation; NTLM omits TCP/IP detail.
                "workstation": "" if kerberos else rng.choice(_HOSTS),
                "source_ip": _internal_ip(rng) if kerberos else "",
                "logon_id": logon_id,
            },
        )

    def benign_process(self, ts: int, logon_id: str = "") -> TelemetryEnvelope:
        rng = self.rng
        return TelemetryEnvelope(
            kind=TelemetryKind.PROCESS,
            severity=AlertSeverity.INFO,
            payload={
                "ts": ts,
                "host": rng.choice(_HOSTS),
                "pid": rng.randint(1000, 9000),
                "parent_pid": rng.randint(400, 999),
                "process_name": rng.choice(_BENIGN_PROCS),
                "command_line": "",
                "user": rng.choice(_USERS),
                "logon_id": logon_id,
            },
        )

    def benign_netflow(self, ts: int) -> TelemetryEnvelope:
        rng = self.rng
        return TelemetryEnvelope(
            kind=TelemetryKind.NETFLOW,
            severity=AlertSeverity.INFO,
            payload={
                "ts": ts,
                "host": rng.choice(_HOSTS),
                "src_ip": _internal_ip(rng),
                "dst_ip": _internal_ip(rng),
                "src_port": rng.randint(1024, 65535),
                "dst_port": rng.choice([80, 443, 445, 53]),
                "protocol": "TCP",
                "bytes_sent": rng.randint(64, 4096),
                "bytes_recv": rng.randint(64, 65536),
            },
        )

    def benign_batch(self, n: int, base_ts: int | None = None) -> list[TelemetryEnvelope]:
        base = base_ts if base_ts is not None else now_ms()
        out: list[TelemetryEnvelope] = []
        for i in range(n):
            ts = base + i
            roll = self.rng.random()
            if roll < 0.34:
                out.append(self.benign_logon(ts))
            elif roll < 0.67:
                out.append(self.benign_process(ts))
            else:
                out.append(self.benign_netflow(ts))
        return out

    # -- attack scenarios ------------------------------------------------------

    def brute_force(
        self, *, target_host: str = "DC-01", source_ip: str = "203.0.113.66",
        attempts: int = 40, base_ts: int | None = None,
    ) -> list[TelemetryEnvelope]:
        """A burst of NTLM network logons from a single external IP (one tight window).

        Detection signal: high logon volume from one ``source_ip`` against many users.
        """
        base = base_ts if base_ts is not None else now_ms()
        out: list[TelemetryEnvelope] = []
        for i in range(attempts):
            out.append(
                TelemetryEnvelope(
                    kind=TelemetryKind.LOGON,
                    severity=AlertSeverity.MEDIUM,
                    payload={
                        "ts": base + i * 50,  # ~20/sec
                        "host": target_host,
                        "user": self.rng.choice(_USERS),
                        "logon_type": LogonType.NETWORK,
                        "logon_process": "NtLmSsp",
                        "auth_package": "NTLM",
                        "workstation": "ATTACKER",
                        "source_ip": source_ip,
                        "logon_id": f"0x{self.rng.randint(0x10000, 0xFFFFFF):x}",
                    },
                )
            )
        return out

    def ransomware(
        self, *, host: str = "FILE-01", user: str = "svc_backup",
        base_ts: int | None = None,
    ) -> list[TelemetryEnvelope]:
        """A correlated ransomware chain: logon -> malicious process -> C2 beacon.

        The 4624 and 4688 share a ``logon_id``; the 4688 carries a known-bad process
        and a shadow-copy-deletion command line; the netflow beacons to a C2 IP.
        """
        base = base_ts if base_ts is not None else now_ms()
        logon_id = f"0x{self.rng.randint(0x10000, 0xFFFFFF):x}"
        c2 = self.rng.choice(sorted(C2_IPS))
        bad = self.rng.choice(sorted(KNOWN_BAD_PROCESSES))
        return [
            TelemetryEnvelope(
                kind=TelemetryKind.LOGON,
                severity=AlertSeverity.HIGH,
                payload={
                    "ts": base,
                    "host": host,
                    "user": user,
                    "logon_type": LogonType.REMOTE_INTERACTIVE,
                    "logon_process": "User32",
                    "auth_package": "Negotiate",
                    "workstation": "ATTACKER",
                    "source_ip": c2,
                    "logon_id": logon_id,
                },
            ),
            TelemetryEnvelope(
                kind=TelemetryKind.PROCESS,
                severity=AlertSeverity.CRITICAL,
                payload={
                    "ts": base + 500,
                    "host": host,
                    "pid": self.rng.randint(4000, 9000),
                    "parent_pid": self.rng.randint(400, 999),
                    "process_name": rf"C:\Users\Public\{bad}",
                    "command_line": "vssadmin.exe delete shadows /all /quiet",
                    "user": user,
                    "logon_id": logon_id,
                },
            ),
            TelemetryEnvelope(
                kind=TelemetryKind.NETFLOW,
                severity=AlertSeverity.HIGH,
                payload={
                    "ts": base + 800,
                    "host": host,
                    "src_ip": _internal_ip(self.rng),
                    "dst_ip": c2,
                    "src_port": self.rng.randint(1024, 65535),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": self.rng.randint(50_000, 500_000),
                    "bytes_recv": self.rng.randint(1000, 5000),
                },
            ),
        ]

    # -- scenario composition --------------------------------------------------

    def build_scenario(
        self, scenario: Scenario, difficulty: Difficulty = Difficulty.MEDIUM,
        base_ts: int | None = None,
    ) -> list[TelemetryEnvelope]:
        """Compose an attack interleaved with difficulty-scaled benign noise."""
        base = base_ts if base_ts is not None else now_ms()
        noise = self.benign_batch(20 * int(difficulty), base_ts=base)
        if scenario is Scenario.BENIGN:
            attack: list[TelemetryEnvelope] = []
        elif scenario is Scenario.BRUTE_FORCE:
            attack = self.brute_force(base_ts=base + 5)
        elif scenario is Scenario.RANSOMWARE:
            attack = self.ransomware(base_ts=base + 5)
        else:  # pragma: no cover - exhaustive
            raise ValueError(scenario)
        combined = noise + attack
        combined.sort(key=lambda e: e.payload["ts"])
        return combined
