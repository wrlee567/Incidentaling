"""Durable, replayable event history backed by SQLite.

This is the spine of the Temporal-style engine. Every meaningful transition is appended
as an immutable event. A workflow's progress is therefore fully reconstructable: if a
worker dies mid-run, a replacement loads the history and resumes from the last committed
checkpoint, so no containment step is ever silently lost.

Two design points the spec calls out:

* **Atomic state + queue commit.** When a step completes, we write its ``ACTIVITY_COMPLETED``
  event AND enqueue the now-unblocked successor steps in the *same* SQLite transaction.
  Because state and the local task queue live in one shard, the commit is atomic without
  a distributed two-phase commit.
* **Replay.** ``completed_steps`` and ``started_steps`` are derived purely from the event
  log, never from in-memory state.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter

from app.models import now_ms

WORKFLOW_STARTED = "WORKFLOW_STARTED"
ACTIVITY_STARTED = "ACTIVITY_STARTED"
ACTIVITY_COMPLETED = "ACTIVITY_COMPLETED"
ACTIVITY_FAILED = "ACTIVITY_FAILED"
WORKFLOW_COMPLETED = "WORKFLOW_COMPLETED"


class EventHistory:
    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                run_id     TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                status     TEXT NOT NULL,
                definition TEXT NOT NULL,
                trigger    TEXT NOT NULL,
                created_ts INTEGER NOT NULL,
                updated_ts INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workflow_events (
                seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id  TEXT NOT NULL,
                ts      INTEGER NOT NULL,
                type    TEXT NOT NULL,
                step_id TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '{}'
            );
            -- The "localized transfer queue": lives in the same shard as the state.
            CREATE TABLE IF NOT EXISTS local_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT NOT NULL,
                step_id     TEXT NOT NULL,
                enqueued_ts INTEGER NOT NULL,
                claimed     INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self.conn.commit()

    # -- run lifecycle ---------------------------------------------------------

    def start_run(self, run_id: str, name: str, definition: dict, trigger: dict) -> None:
        ts = now_ms()
        with self.conn:  # transaction
            self.conn.execute(
                "INSERT INTO workflow_runs(run_id,name,status,definition,trigger,created_ts,updated_ts)"
                " VALUES (?,?,?,?,?,?,?)",
                (run_id, name, "RUNNING", json.dumps(definition), json.dumps(trigger), ts, ts),
            )
            self._append(run_id, WORKFLOW_STARTED, payload=trigger)

    def set_status(self, run_id: str, status: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE workflow_runs SET status=?, updated_ts=? WHERE run_id=?",
                (status, now_ms(), run_id),
            )

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        cur = self.conn.execute("SELECT * FROM workflow_runs WHERE run_id=?", (run_id,))
        return cur.fetchone()

    # -- events ----------------------------------------------------------------

    def _append(self, run_id: str, type_: str, step_id: str = "", payload: dict | None = None) -> None:
        self.conn.execute(
            "INSERT INTO workflow_events(run_id,ts,type,step_id,payload) VALUES (?,?,?,?,?)",
            (run_id, now_ms(), type_, step_id, json.dumps(payload or {})),
        )

    def record_started(self, run_id: str, step_id: str) -> None:
        with self.conn:
            self._append(run_id, ACTIVITY_STARTED, step_id)

    def commit_step(self, run_id: str, step_id: str, result: dict, next_steps: list[str]) -> None:
        """Atomically record completion AND enqueue unblocked successors."""
        ts = now_ms()
        with self.conn:  # single transaction: state + queue in the same shard
            self._append(run_id, ACTIVITY_COMPLETED, step_id, result)
            for nxt in next_steps:
                self.conn.execute(
                    "INSERT INTO local_queue(run_id,step_id,enqueued_ts) VALUES (?,?,?)",
                    (run_id, nxt, ts),
                )

    def record_failed(self, run_id: str, step_id: str, error: str) -> None:
        with self.conn:
            self._append(run_id, ACTIVITY_FAILED, step_id, {"error": error})

    def complete_workflow(self, run_id: str, result: dict) -> None:
        with self.conn:
            self._append(run_id, WORKFLOW_COMPLETED, payload=result)
            self.conn.execute(
                "UPDATE workflow_runs SET status='COMPLETED', updated_ts=? WHERE run_id=?",
                (now_ms(), run_id),
            )

    def events(self, run_id: str) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM workflow_events WHERE run_id=? ORDER BY seq", (run_id,)
        )
        return cur.fetchall()

    # -- replay-derived state --------------------------------------------------

    def completed_steps(self, run_id: str) -> set[str]:
        cur = self.conn.execute(
            "SELECT step_id FROM workflow_events WHERE run_id=? AND type=?",
            (run_id, ACTIVITY_COMPLETED),
        )
        return {r["step_id"] for r in cur.fetchall()}

    def attempt_counts(self, run_id: str) -> Counter:
        cur = self.conn.execute(
            "SELECT step_id FROM workflow_events WHERE run_id=? AND type=?",
            (run_id, ACTIVITY_STARTED),
        )
        return Counter(r["step_id"] for r in cur.fetchall())
