"""Tests for the mock columnar store and the typed telemetry models."""

from __future__ import annotations

import pytest

from app.models import LogonEvent, ProcessCreationEvent, TelemetryEnvelope, TelemetryKind
from app.store import ColumnarTable, ColumnSpec, Dtype

_MS_PER_DAY = 86_400_000


def make_table(ttl_days: int | None = None) -> ColumnarTable:
    return ColumnarTable(
        schema=[
            ColumnSpec("ts", Dtype.UINT64),
            ColumnSpec("host", Dtype.LOWCARD_STR, default=""),
            ColumnSpec("user", Dtype.LOWCARD_STR, default=""),
            ColumnSpec("severity", Dtype.UINT8),
            ColumnSpec("pid", Dtype.UINT32),
            ColumnSpec("cmd", Dtype.STR, default=""),
        ],
        time_column="ts",
        ttl_days=ttl_days,
    )


def test_insert_and_query_roundtrip():
    t = make_table()
    t.insert({"ts": 1000, "host": "ws1", "user": "alice", "severity": 4, "pid": 42, "cmd": "x.exe"})
    rows = t.query()
    assert len(rows) == 1
    assert rows[0] == {
        "ts": 1000, "host": "ws1", "user": "alice", "severity": 4, "pid": 42, "cmd": "x.exe",
    }


def test_select_reads_only_requested_columns():
    t = make_table()
    t.insert({"ts": 1, "host": "ws1", "user": "alice", "severity": 1, "pid": 1, "cmd": "a"})
    rows = t.query(columns=["host", "severity"])
    assert rows == [{"host": "ws1", "severity": 1}]


def test_low_cardinality_dictionary_encoding():
    t = make_table()
    for i in range(100):
        t.insert({"ts": i, "host": "ws1", "user": "alice", "severity": 0, "pid": i, "cmd": ""})
    # 100 rows, but only one distinct host/user -> dictionaries hold a single entry.
    assert t._rev_dicts["host"] == ["ws1"]
    assert t._rev_dicts["user"] == ["alice"]
    assert t.row_count == 100


def test_equality_filter_on_low_cardinality():
    t = make_table()
    t.insert({"ts": 1, "host": "ws1", "user": "alice", "severity": 0, "pid": 1, "cmd": ""})
    t.insert({"ts": 2, "host": "ws2", "user": "bob", "severity": 0, "pid": 2, "cmd": ""})
    rows = t.query(columns=["host"], where={"user": "bob"})
    assert rows == [{"host": "ws2"}]


def test_filter_on_unseen_value_returns_empty_fast():
    t = make_table()
    t.insert({"ts": 1, "host": "ws1", "user": "alice", "severity": 0, "pid": 1, "cmd": ""})
    assert t.query(where={"user": "nobody"}) == []
    assert t.count(where={"user": "nobody"}) == 0


def test_time_range_query_and_partition_pruning():
    t = make_table()
    # Spread rows across three different day buckets.
    for day in range(3):
        t.insert({"ts": day * _MS_PER_DAY + 10, "host": "h", "user": "u",
                  "severity": 0, "pid": day, "cmd": ""})
    assert t.partition_count == 3
    rows = t.query(start_ms=_MS_PER_DAY, end_ms=_MS_PER_DAY + 100)
    assert len(rows) == 1
    assert rows[0]["pid"] == 1


def test_count_matches_query_length():
    t = make_table()
    for i in range(50):
        t.insert({"ts": i, "host": "h", "user": "u",
                  "severity": (i % 5), "pid": i, "cmd": ""})
    assert t.count(where={"severity": 4}) == len(t.query(where={"severity": 4}))


def test_ttl_evicts_old_partitions():
    t = make_table(ttl_days=1)
    now = 10 * _MS_PER_DAY
    t.insert({"ts": now - 5 * _MS_PER_DAY, "host": "h", "user": "u",
              "severity": 0, "pid": 1, "cmd": ""})  # old
    t.insert({"ts": now, "host": "h", "user": "u",
              "severity": 0, "pid": 2, "cmd": ""})  # fresh
    evicted = t.enforce_ttl(now_ms=now)
    assert evicted == 1
    assert t.row_count == 1
    assert t.query()[0]["pid"] == 2


def test_no_nulls_uses_default():
    t = make_table()
    # Omit 'cmd' entirely; the declared default ("") must be substituted, never NULL.
    t.insert({"ts": 1, "host": "h", "user": "u", "severity": 0, "pid": 1})
    assert t.query()[0]["cmd"] == ""


def test_precision_typing_footprint():
    t = make_table()
    for i in range(1000):
        t.insert({"ts": i, "host": "h", "user": "u",
                  "severity": 0, "pid": i, "cmd": ""})
    fp = t.memory_footprint()
    # severity is UInt8 (1 byte/row); ts is UInt64 (8 bytes/row).
    assert fp["severity"] == 1000
    assert fp["ts"] == 8000


def test_unknown_column_raises():
    t = make_table()
    t.insert({"ts": 1, "host": "h", "user": "u", "severity": 0, "pid": 1, "cmd": ""})
    with pytest.raises(KeyError):
        t.query(columns=["does_not_exist"])


# -- model tests --------------------------------------------------------------

def test_envelope_parses_logon():
    env = TelemetryEnvelope(
        kind=TelemetryKind.LOGON,
        payload={"host": "ws1", "user": "alice", "logon_id": "0x3e7"},
    )
    ev = env.parse()
    assert isinstance(ev, LogonEvent)
    assert ev.event_id == 4624
    assert ev.workstation == ""  # default, no NULL


def test_envelope_parses_process_and_links_logon():
    env = TelemetryEnvelope(
        kind=TelemetryKind.PROCESS,
        payload={"host": "ws1", "pid": 1337, "process_name": "C:\\evil.exe", "logon_id": "0x3e7"},
    )
    ev = env.parse()
    assert isinstance(ev, ProcessCreationEvent)
    assert ev.event_id == 4688
    assert ev.logon_id == "0x3e7"


def test_envelope_forbids_extra_fields():
    with pytest.raises(Exception):
        TelemetryEnvelope(kind=TelemetryKind.LOGON, payload={}, bogus=1)
