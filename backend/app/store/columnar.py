"""An in-process columnar table that models the *behavior* of ClickHouse.

This is a teaching mock, not a database. It deliberately reproduces the design
decisions a real columnar SIEM backend depends on, and exposes them so they can be
measured and reasoned about:

* **Column-oriented physical layout.** Each column is a contiguous ``numpy`` array.
  A query reads only the arrays it references — irrelevant columns are never touched.
  This is the whole reason columnar stores win on analytical (OLAP) scans.

* **Precision data typing.** Columns declare an exact width (``UInt8`` .. ``UInt64``).
  Choosing the smallest type that fits the value range compounds into large savings
  in disk I/O, decompression, and RAM cache pressure across billions of rows.
  :meth:`ColumnarTable.memory_footprint` lets you see the difference.

* **No NULLs.** Real ClickHouse ``Nullable`` columns carry a parallel ``UInt8`` mask,
  doubling bookkeeping. We forbid NULLs and require a sensible default per column.

* **Low-cardinality dictionary encoding.** Repetitive strings (hostnames, usernames)
  are dictionary-encoded to small integer ids, mirroring ``LowCardinality(String)``.

* **Time-based partitioning + TTL.** Rows are bucketed into day partitions derived
  from a timestamp column. Time-bounded queries prune whole partitions, and
  :meth:`enforce_ttl` drops partitions older than the retention window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable

import numpy as np

_MS_PER_DAY = 86_400_000


class Dtype(StrEnum):
    """Supported column physical types and their numpy mapping."""

    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    INT64 = "int64"
    # Strings stored as dictionary-encoded uint32 ids (LowCardinality-style).
    LOWCARD_STR = "lowcard_str"
    # Strings stored verbatim (object array) for high-cardinality fields.
    STR = "str"

    @property
    def numpy_dtype(self) -> np.dtype:
        match self:
            case Dtype.LOWCARD_STR:
                return np.dtype(np.uint32)  # stores dictionary ids
            case Dtype.STR:
                return np.dtype(object)
            case _:
                return np.dtype(self.value)


@dataclass(frozen=True)
class ColumnSpec:
    """Static definition of one column. ``default`` replaces what would be a NULL."""

    name: str
    dtype: Dtype
    default: Any = 0

    def __post_init__(self) -> None:
        if self.dtype in (Dtype.STR, Dtype.LOWCARD_STR) and not isinstance(self.default, str):
            raise ValueError(f"string column {self.name!r} needs a string default")


@dataclass
class _Partition:
    """One time bucket holding amortized-growth numpy column arrays."""

    columns: dict[str, np.ndarray] = field(default_factory=dict)
    size: int = 0  # logical row count (arrays may be over-allocated)

    def capacity(self) -> int:
        any_col = next(iter(self.columns.values()), None)
        return 0 if any_col is None else len(any_col)


class ColumnarTable:
    """A single statically-typed, time-partitioned columnar table."""

    def __init__(
        self,
        schema: Iterable[ColumnSpec],
        *,
        time_column: str = "ts",
        ttl_days: int | None = None,
    ) -> None:
        self.schema: list[ColumnSpec] = list(schema)
        self._by_name = {c.name: c for c in self.schema}
        if time_column not in self._by_name:
            raise ValueError(f"time_column {time_column!r} not in schema")
        if self._by_name[time_column].dtype not in (Dtype.UINT64, Dtype.INT64):
            raise ValueError("time_column must be a 64-bit integer (epoch ms)")
        self.time_column = time_column
        self.ttl_days = ttl_days

        # Per low-cardinality column: forward dict (value -> id) and reverse list.
        self._dicts: dict[str, dict[str, int]] = {
            c.name: {} for c in self.schema if c.dtype is Dtype.LOWCARD_STR
        }
        self._rev_dicts: dict[str, list[str]] = {
            c.name: [] for c in self.schema if c.dtype is Dtype.LOWCARD_STR
        }
        # Partitions keyed by day-bucket integer, kept sorted for pruning.
        self._partitions: dict[int, _Partition] = {}

    # -- ingestion -------------------------------------------------------------

    def _encode(self, col: ColumnSpec, value: Any) -> Any:
        """Encode a single Python value into its stored representation."""
        if value is None:
            value = col.default  # no NULLs: substitute the declared default
        if col.dtype is Dtype.LOWCARD_STR:
            fwd, rev = self._dicts[col.name], self._rev_dicts[col.name]
            sid = fwd.get(value)
            if sid is None:
                sid = len(rev)
                fwd[value] = sid
                rev.append(value)
            return sid
        return value

    def _ensure_capacity(self, part: _Partition, needed: int) -> None:
        if part.capacity() >= needed:
            return
        new_cap = max(8, part.capacity() * 2, needed)
        for col in self.schema:
            old = part.columns.get(col.name)
            grown = np.empty(new_cap, dtype=col.dtype.numpy_dtype)
            if old is not None:
                grown[: part.size] = old[: part.size]
            part.columns[col.name] = grown

    def insert(self, row: dict[str, Any]) -> None:
        """Append one row, routed to the partition for its timestamp."""
        ts = int(row[self.time_column])
        bucket = ts // _MS_PER_DAY
        part = self._partitions.get(bucket)
        if part is None:
            part = self._partitions[bucket] = _Partition()
        self._ensure_capacity(part, part.size + 1)
        idx = part.size
        for col in self.schema:
            part.columns[col.name][idx] = self._encode(col, row.get(col.name))
        part.size += 1

    def insert_many(self, rows: Iterable[dict[str, Any]]) -> int:
        n = 0
        for r in rows:
            self.insert(r)
            n += 1
        return n

    # -- querying --------------------------------------------------------------

    def _decode(self, col: ColumnSpec, value: Any) -> Any:
        if col.dtype is Dtype.LOWCARD_STR:
            return self._rev_dicts[col.name][int(value)]
        if col.dtype is Dtype.STR:
            return value
        return int(value)

    def _relevant_partitions(
        self, start_ms: int | None, end_ms: int | None
    ) -> list[_Partition]:
        """Partition pruning: only return buckets overlapping [start, end]."""
        lo = (start_ms // _MS_PER_DAY) if start_ms is not None else None
        hi = (end_ms // _MS_PER_DAY) if end_ms is not None else None
        out = []
        for bucket in sorted(self._partitions):
            if lo is not None and bucket < lo:
                continue
            if hi is not None and bucket > hi:
                continue
            out.append(self._partitions[bucket])
        return out

    def query(
        self,
        *,
        columns: list[str] | None = None,
        start_ms: int | None = None,
        end_ms: int | None = None,
        where: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Scan the table, reading ONLY the columns referenced.

        ``where`` is a simple equality predicate map (column -> value), evaluated on the
        encoded representation for speed (we encode the literal once, then compare ids).
        """
        select = columns or [c.name for c in self.schema]
        unknown = set(select) - set(self._by_name)
        if unknown:
            raise KeyError(f"unknown columns: {sorted(unknown)}")

        # Columns we must physically read = selected ∪ filtered ∪ time (for bounds).
        where = where or {}
        touched = set(select) | set(where) | {self.time_column}

        # Pre-encode filter literals into stored representation.
        enc_filters: dict[str, Any] = {}
        for name, val in where.items():
            col = self._by_name[name]
            if col.dtype is Dtype.LOWCARD_STR and val not in self._dicts[col.name]:
                return []  # value never seen -> no rows can match
            enc_filters[name] = self._encode(col, val) if col.dtype is Dtype.LOWCARD_STR else val

        results: list[dict[str, Any]] = []
        for part in self._relevant_partitions(start_ms, end_ms):
            n = part.size
            if n == 0:
                continue
            ts_arr = part.columns[self.time_column][:n]
            mask = np.ones(n, dtype=bool)
            if start_ms is not None:
                mask &= ts_arr >= start_ms
            if end_ms is not None:
                mask &= ts_arr <= end_ms
            for name, enc_val in enc_filters.items():
                mask &= part.columns[name][:n] == enc_val
            idxs = np.nonzero(mask)[0]
            # Only materialize the SELECTed columns for matching rows.
            cols_data = {name: part.columns[name][:n] for name in select if name in touched}
            for i in idxs:
                results.append(
                    {name: self._decode(self._by_name[name], cols_data[name][i]) for name in select}
                )
                if limit is not None and len(results) >= limit:
                    return results
        return results

    def count(
        self, *, start_ms: int | None = None, end_ms: int | None = None,
        where: dict[str, Any] | None = None,
    ) -> int:
        """Efficient COUNT that never materializes rows."""
        where = where or {}
        enc_filters: dict[str, Any] = {}
        for name, val in where.items():
            col = self._by_name[name]
            if col.dtype is Dtype.LOWCARD_STR and val not in self._dicts[col.name]:
                return 0
            enc_filters[name] = self._encode(col, val) if col.dtype is Dtype.LOWCARD_STR else val
        total = 0
        for part in self._relevant_partitions(start_ms, end_ms):
            n = part.size
            if n == 0:
                continue
            ts_arr = part.columns[self.time_column][:n]
            mask = np.ones(n, dtype=bool)
            if start_ms is not None:
                mask &= ts_arr >= start_ms
            if end_ms is not None:
                mask &= ts_arr <= end_ms
            for name, enc_val in enc_filters.items():
                mask &= part.columns[name][:n] == enc_val
            total += int(mask.sum())
        return total

    # -- lifecycle -------------------------------------------------------------

    def enforce_ttl(self, *, now_ms: int) -> int:
        """Drop whole partitions older than ``ttl_days``. Returns rows evicted."""
        if self.ttl_days is None:
            return 0
        cutoff_bucket = (now_ms - self.ttl_days * _MS_PER_DAY) // _MS_PER_DAY
        evicted = 0
        for bucket in [b for b in self._partitions if b < cutoff_bucket]:
            evicted += self._partitions.pop(bucket).size
        return evicted

    # -- introspection ---------------------------------------------------------

    @property
    def row_count(self) -> int:
        return sum(p.size for p in self._partitions.values())

    @property
    def partition_count(self) -> int:
        return len(self._partitions)

    def memory_footprint(self) -> dict[str, int]:
        """Approximate stored bytes per column (logical rows only).

        Demonstrates why precision typing matters: a UInt8 column costs 1 byte/row,
        a UInt64 column 8 bytes/row, for identical information when the range fits.
        """
        out: dict[str, int] = {}
        for col in self.schema:
            width = col.dtype.numpy_dtype.itemsize if col.dtype is not Dtype.STR else 16
            out[col.name] = width * self.row_count
        return out
