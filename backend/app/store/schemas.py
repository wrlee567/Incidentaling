"""Concrete columnar table schemas for each telemetry kind.

One table per telemetry kind keeps each schema tight and precisely typed (the whole
point of the columnar design). Correlation joins across tables on ``logon_id``.

Every column uses the smallest type that fits, and string columns are
low-cardinality dictionary-encoded unless they are genuinely high-cardinality
(command lines, full process paths, raw logon ids).
"""

from __future__ import annotations

from app.models import TelemetryKind
from app.store.columnar import ColumnarTable, ColumnSpec, Dtype

# Default retention for the simulator. Real deployments tune this per source and
# balance compliance mandates against storage cost.
DEFAULT_TTL_DAYS = 30


def _logon_schema() -> list[ColumnSpec]:
    return [
        ColumnSpec("ts", Dtype.UINT64),
        ColumnSpec("event_id", Dtype.UINT16, default=4624),
        ColumnSpec("severity", Dtype.UINT8),
        ColumnSpec("host", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("user", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("logon_type", Dtype.UINT8),
        ColumnSpec("logon_process", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("auth_package", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("workstation", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("source_ip", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("logon_id", Dtype.STR, default=""),
    ]


def _process_schema() -> list[ColumnSpec]:
    return [
        ColumnSpec("ts", Dtype.UINT64),
        ColumnSpec("event_id", Dtype.UINT16, default=4688),
        ColumnSpec("severity", Dtype.UINT8),
        ColumnSpec("host", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("pid", Dtype.UINT32),
        ColumnSpec("parent_pid", Dtype.UINT32),
        ColumnSpec("process_name", Dtype.STR, default=""),
        ColumnSpec("command_line", Dtype.STR, default=""),
        ColumnSpec("user", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("logon_id", Dtype.STR, default=""),
    ]


def _netflow_schema() -> list[ColumnSpec]:
    return [
        ColumnSpec("ts", Dtype.UINT64),
        ColumnSpec("event_id", Dtype.UINT16, default=5156),
        ColumnSpec("severity", Dtype.UINT8),
        ColumnSpec("host", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("src_ip", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("dst_ip", Dtype.LOWCARD_STR, default=""),
        ColumnSpec("src_port", Dtype.UINT16),
        ColumnSpec("dst_port", Dtype.UINT16),
        ColumnSpec("protocol", Dtype.LOWCARD_STR, default="TCP"),
        ColumnSpec("bytes_sent", Dtype.UINT64),
        ColumnSpec("bytes_recv", Dtype.UINT64),
    ]


_SCHEMA_BUILDERS = {
    TelemetryKind.LOGON: _logon_schema,
    TelemetryKind.PROCESS: _process_schema,
    TelemetryKind.NETFLOW: _netflow_schema,
}


def build_tables(ttl_days: int | None = DEFAULT_TTL_DAYS) -> dict[TelemetryKind, ColumnarTable]:
    """Instantiate a fresh set of telemetry tables keyed by kind."""
    return {
        kind: ColumnarTable(builder(), time_column="ts", ttl_days=ttl_days)
        for kind, builder in _SCHEMA_BUILDERS.items()
    }
