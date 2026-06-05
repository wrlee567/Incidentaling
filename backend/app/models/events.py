"""Strictly-typed telemetry and alert models.

These mirror real-world Security telemetry so the simulator produces authentic
data for the SIEM/SOAR pipeline:

* ``LogonEvent``  -> Windows Security Event ID 4624 (an account was logged on)
* ``ProcessCreationEvent`` -> Windows Security Event ID 4688 (a new process was created)
* ``NetFlowEvent`` -> a TCP/IP network flow record

Every event carries a ``host`` and a millisecond ``ts`` so the columnar store can
partition by time and the correlation engine can stitch events into sessions.
"""

from __future__ import annotations

import time
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


def now_ms() -> int:
    """Current wall-clock time in epoch milliseconds (the canonical event clock)."""
    return int(time.time() * 1000)


class TelemetryKind(StrEnum):
    """Discriminator for the kind of telemetry carried in an envelope."""

    LOGON = "logon"  # Windows 4624
    PROCESS = "process"  # Windows 4688
    NETFLOW = "netflow"  # TCP/IP flow


class AlertSeverity(IntEnum):
    """Severity ordering used to decide push (critical) vs pull (routine) ingestion.

    Kept as a small int on purpose: it maps to a ``uint8`` column in the store.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class LogonType(IntEnum):
    """Subset of Windows logon types relevant to detections."""

    INTERACTIVE = 2
    NETWORK = 3  # e.g. SMB / lateral movement
    REMOTE_INTERACTIVE = 10  # RDP


class _Event(BaseModel):
    """Common fields for all telemetry. ``extra='forbid'`` enforces a static schema."""

    model_config = ConfigDict(extra="forbid")

    ts: int = Field(default_factory=now_ms, description="Epoch milliseconds.")
    host: str = Field(..., description="Endpoint hostname that produced the event.")


class LogonEvent(_Event):
    """Windows Security Event ID 4624 — an account was successfully logged on.

    Note the protocol quirks the simulator reproduces:
      * Kerberos network logons frequently omit ``workstation``.
      * NTLM logons frequently lack full ``source_ip`` / TCP-IP detail.
    These are encoded as empty-string defaults (the store has no NULLs).
    """

    event_id: int = Field(default=4624, frozen=True)
    user: str
    logon_type: LogonType = LogonType.NETWORK
    logon_process: str = Field(default="Advapi", description="Trusted logon process.")
    auth_package: str = Field(default="Kerberos", description="Kerberos | NTLM | Negotiate.")
    workstation: str = Field(default="", description="Omitted for many Kerberos logons.")
    source_ip: str = Field(default="", description="Omitted for many NTLM logons.")
    logon_id: str = Field(..., description="Session id; links to 4688 process events.")


class ProcessCreationEvent(_Event):
    """Windows Security Event ID 4688 — a new process was created.

    ``logon_id`` is the join key back to the originating :class:`LogonEvent`, letting
    the correlation engine answer "which network identity executed this binary?".
    """

    event_id: int = Field(default=4688, frozen=True)
    pid: int
    parent_pid: int = 0
    process_name: str = Field(..., description="Full executable path.")
    command_line: str = ""
    user: str = ""
    logon_id: str = Field(default="", description="Links to the 4624 session.")


class NetFlowEvent(_Event):
    """A single TCP/IP network flow observed at the endpoint."""

    event_id: int = Field(default=5156, frozen=True)
    src_ip: str
    dst_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(default="TCP", description="TCP | UDP.")
    bytes_sent: int = Field(default=0, ge=0)
    bytes_recv: int = Field(default=0, ge=0)


class TelemetryEnvelope(BaseModel):
    """Wire format for the ingestion API.

    A discriminated union would be cleaner with Pydantic v2 ``Field(discriminator=...)``
    but keeping an explicit ``kind`` plus an opaque ``payload`` mirrors how a real
    collector forwards heterogeneous JSON to a typed parser at the edge.
    """

    model_config = ConfigDict(extra="forbid")

    kind: TelemetryKind
    severity: AlertSeverity = AlertSeverity.INFO
    payload: dict

    def parse(self) -> _Event:
        """Validate the opaque payload against its concrete typed model."""
        match self.kind:
            case TelemetryKind.LOGON:
                return LogonEvent(**self.payload)
            case TelemetryKind.PROCESS:
                return ProcessCreationEvent(**self.payload)
            case TelemetryKind.NETFLOW:
                return NetFlowEvent(**self.payload)
        raise ValueError(f"unknown telemetry kind: {self.kind}")


class Alert(BaseModel):
    """A correlated detection produced by the SIEM, consumed by the SOAR engine."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    rule: str = Field(..., description="Name of the detection rule that fired.")
    severity: AlertSeverity
    host: str
    user: str = ""
    source_ip: str = ""
    ts: int = Field(default_factory=now_ms)
    detail: str = ""
