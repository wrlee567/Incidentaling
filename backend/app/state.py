"""Shared application state: the telemetry tables, the pull spool, and alerts.

A single ``AppState`` instance is created per FastAPI app and threaded through routes
via dependency injection. Keeping it explicit (rather than module globals) makes the
whole pipeline trivially testable: a test constructs its own ``AppState``.
"""

from __future__ import annotations

from app.ingestion.buffer import PullBuffer
from app.models import Alert, AlertSeverity, TelemetryEnvelope, TelemetryKind
from app.orchestration import EventHistory, SimulatedEnvironment, WorkflowEngine
from app.playbooks import playbook_for_alert
from app.store import build_tables
from app.store.columnar import ColumnarTable

# Severity at/above which the pull path is disallowed: such events MUST be pushed
# so the SOAR engine can react in near-real-time.
PUSH_REQUIRED_SEVERITY = AlertSeverity.HIGH


class AppState:
    def __init__(self, ttl_days: int | None = None, history_path: str = ":memory:") -> None:
        self.tables: dict[TelemetryKind, ColumnarTable] = build_tables(ttl_days=ttl_days)
        self.pull_buffer = PullBuffer()
        self.alerts: list[Alert] = []
        # Hook set by the correlation layer (Phase 4); called for every ingested event.
        self.on_event = None  # type: ignore[var-annotated]

        # SOAR orchestration: one durable history + simulated environment + engine.
        self.environment = SimulatedEnvironment()
        self.history = EventHistory(history_path)
        self.engine = WorkflowEngine(self.history, self.environment)
        # alert_id -> run_id, so each alert triggers its playbook at most once.
        self.alert_runs: dict[str, str] = {}

    def ingest(self, env: TelemetryEnvelope) -> None:
        """Validate an envelope and write it to the appropriate columnar table.

        This is the single write path shared by both push and pull, so the storage
        layer never needs to know which transport delivered the data.
        """
        event = env.parse()  # raises if the payload violates the typed schema
        table = self.tables[env.kind]
        row = {**event.model_dump(), "severity": int(env.severity)}
        table.insert(row)
        if self.on_event is not None:
            self.on_event(env.kind, event, env.severity)

    def raise_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def respond(self) -> list[dict]:
        """Trigger the matching playbook for every alert that has no run yet.

        Idempotent at the alert level: an alert that already launched a run is skipped,
        so calling /respond repeatedly never double-contains an incident.
        """
        launched: list[dict] = []
        for alert in self.alerts:
            if alert.alert_id in self.alert_runs:
                continue
            definition = playbook_for_alert(alert)
            if definition is None:
                continue
            run_id = self.engine.start(definition, trigger={"alert_id": alert.alert_id})
            self.alert_runs[alert.alert_id] = run_id
            launched.append(
                {"alert_id": alert.alert_id, "rule": alert.rule,
                 "playbook": definition.name, "run_id": run_id}
            )
        return launched
