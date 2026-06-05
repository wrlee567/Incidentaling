"""Detection rules that turn raw telemetry into correlated alerts.

This is the SIEM's analytical core. Detection runs as a batch scan over the columnar
store (the natural fit for OLAP) and emits :class:`Alert` objects, which the SOAR
engine consumes to trigger playbooks.

Rules implemented:

* ``ransomware.known_bad_process`` — a 4688 whose executable basename matches a known
  ransomware signature. Enriched by joining ``logon_id`` back to the 4624 session to
  recover the originating user and source IP.
* ``auth.brute_force`` — a burst of logons from a single *external* source IP exceeding
  a threshold inside a time window.
* ``net.c2_beacon`` — a netflow to a known command-and-control IP.

Alert ids are deterministic (uuid5 of a stable key) so repeated scans are idempotent
and never raise duplicate alerts.
"""

from __future__ import annotations

import ntpath
import uuid

from app.models import Alert, AlertSeverity
from app.models.events import TelemetryKind
from app.simulation.generator import C2_IPS, KNOWN_BAD_PROCESSES
from app.state import AppState

_ALERT_NS = uuid.UUID("11111111-2222-3333-4444-555555555555")

BRUTE_FORCE_THRESHOLD = 10  # logons from one external IP within the window


def _alert_id(key: str) -> str:
    return str(uuid.uuid5(_ALERT_NS, key))


def _is_external(ip: str) -> bool:
    return bool(ip) and not ip.startswith("10.") and not ip.startswith("192.168.")


class Detector:
    """Runs detection rules against an :class:`AppState` and raises new alerts."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self._seen: set[str] = set()

    def _emit(self, alert: Alert) -> bool:
        """Raise an alert unless its id was already produced (idempotent)."""
        if alert.alert_id in self._seen:
            return False
        self._seen.add(alert.alert_id)
        self.state.raise_alert(alert)
        return True

    def _logon_for(self, logon_id: str) -> dict | None:
        """Join helper: find the 4624 session that owns a ``logon_id``."""
        if not logon_id:
            return None
        rows = self.state.tables[TelemetryKind.LOGON].query(
            columns=["user", "source_ip", "host"], where={"logon_id": logon_id}, limit=1,
        )
        return rows[0] if rows else None

    def run(self, *, start_ms: int | None = None, end_ms: int | None = None) -> list[Alert]:
        """Run all rules over the given window and return the newly raised alerts."""
        new: list[Alert] = []
        new += self._ransomware_rule(start_ms, end_ms)
        new += self._brute_force_rule(start_ms, end_ms)
        new += self._c2_rule(start_ms, end_ms)
        return new

    # -- rules -----------------------------------------------------------------

    def _ransomware_rule(self, start_ms, end_ms) -> list[Alert]:
        out: list[Alert] = []
        rows = self.state.tables[TelemetryKind.PROCESS].query(
            columns=["ts", "host", "user", "process_name", "command_line", "logon_id"],
            start_ms=start_ms, end_ms=end_ms,
        )
        for r in rows:
            basename = ntpath.basename(r["process_name"]).lower()
            if basename not in KNOWN_BAD_PROCESSES:
                continue
            session = self._logon_for(r["logon_id"])
            source_ip = session["source_ip"] if session else ""
            alert = Alert(
                alert_id=_alert_id(f"ransomware:{r['host']}:{r['logon_id']}:{basename}"),
                rule="ransomware.known_bad_process",
                severity=AlertSeverity.CRITICAL,
                host=r["host"],
                user=r["user"] or (session["user"] if session else ""),
                source_ip=source_ip,
                ts=r["ts"],
                detail=f"known ransomware {basename!r}; cmd={r['command_line']!r}",
            )
            if self._emit(alert):
                out.append(alert)
        return out

    def _brute_force_rule(self, start_ms, end_ms) -> list[Alert]:
        out: list[Alert] = []
        rows = self.state.tables[TelemetryKind.LOGON].query(
            columns=["ts", "host", "user", "source_ip"], start_ms=start_ms, end_ms=end_ms,
        )
        by_ip: dict[str, list[dict]] = {}
        for r in rows:
            if _is_external(r["source_ip"]):
                by_ip.setdefault(r["source_ip"], []).append(r)
        for ip, group in by_ip.items():
            if len(group) < BRUTE_FORCE_THRESHOLD:
                continue
            host = group[0]["host"]
            first_ts = min(g["ts"] for g in group)
            alert = Alert(
                alert_id=_alert_id(f"bruteforce:{ip}:{host}:{first_ts}"),
                rule="auth.brute_force",
                severity=AlertSeverity.HIGH,
                host=host,
                source_ip=ip,
                ts=first_ts,
                detail=f"{len(group)} logons from {ip} (threshold {BRUTE_FORCE_THRESHOLD})",
            )
            if self._emit(alert):
                out.append(alert)
        return out

    def _c2_rule(self, start_ms, end_ms) -> list[Alert]:
        out: list[Alert] = []
        rows = self.state.tables[TelemetryKind.NETFLOW].query(
            columns=["ts", "host", "dst_ip", "bytes_sent"], start_ms=start_ms, end_ms=end_ms,
        )
        for r in rows:
            if r["dst_ip"] not in C2_IPS:
                continue
            alert = Alert(
                alert_id=_alert_id(f"c2:{r['host']}:{r['dst_ip']}:{r['ts']}"),
                rule="net.c2_beacon",
                severity=AlertSeverity.HIGH,
                host=r["host"],
                source_ip=r["dst_ip"],
                ts=r["ts"],
                detail=f"beacon to C2 {r['dst_ip']} ({r['bytes_sent']} bytes sent)",
            )
            if self._emit(alert):
                out.append(alert)
        return out
