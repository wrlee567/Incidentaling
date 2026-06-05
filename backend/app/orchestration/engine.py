"""The workflow engine: a deterministic state machine driving a playbook DAG.

The engine is a loop. Each iteration it asks the *event history* (not memory) which
steps are complete, computes which steps are now unblocked, runs them, and atomically
records completion plus enqueues successors. The loop is the single source of truth for
scheduling; the ``local_queue`` table mirrors what a distributed dispatcher would feed
to remote workers.

Durability: because progress lives entirely in the history, a crashed run is resumed by
pointing a fresh engine at the same history and calling :meth:`resume`. Combined with the
idempotent activities in :mod:`environment`, this gives the at-least-once guarantee real
orchestrators provide — a step may run more than once, but the world ends up in one state.
"""

from __future__ import annotations

import uuid
from typing import Callable

from app.orchestration.dag import WorkflowDefinition
from app.orchestration.environment import ACTIVITY_REGISTRY, Activity, SimulatedEnvironment
from app.orchestration.history import ACTIVITY_COMPLETED, EventHistory


class CrashError(RuntimeError):
    """Injected to simulate a worker dying after a side effect, before its ack."""


# A fault injector: (step_id, attempt) -> None, may raise CrashError.
FaultInjector = Callable[[str, int], None]


class WorkflowEngine:
    def __init__(
        self,
        history: EventHistory,
        environment: SimulatedEnvironment,
        registry: dict[str, Activity] | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self.history = history
        self.env = environment
        self.registry = registry or ACTIVITY_REGISTRY
        self.fault_injector = fault_injector

    def start(self, definition: WorkflowDefinition, trigger: dict) -> str:
        """Begin a new run and drive it to completion (or until a crash is injected)."""
        run_id = str(uuid.uuid4())
        self.history.start_run(run_id, definition.name, definition.model_dump(), trigger)
        self._drive(run_id, definition)
        return run_id

    def resume(self, run_id: str) -> None:
        """Resume a previously-started run from its durable history."""
        run = self.history.get_run(run_id)
        if run is None:
            raise KeyError(f"unknown run {run_id}")
        definition = WorkflowDefinition.model_validate_json(run["definition"])
        self._drive(run_id, definition)

    # -- internals -------------------------------------------------------------

    def _drive(self, run_id: str, definition: WorkflowDefinition) -> None:
        while True:
            completed = self.history.completed_steps(run_id)
            ready = definition.ready_steps(completed)
            if not ready:
                break
            for step_id in ready:
                self._execute(run_id, definition, step_id)

        if self.history.completed_steps(run_id) == {s.id for s in definition.steps}:
            self.history.complete_workflow(run_id, self._aggregate_result(run_id))

    def _execute(self, run_id: str, definition: WorkflowDefinition, step_id: str) -> None:
        step = definition.step(step_id)
        activity = self.registry[step.activity]
        attempt = self.history.attempt_counts(run_id)[step_id] + 1

        self.history.record_started(run_id, step_id)
        result = activity(self.env, step.params)  # idempotent side effect

        # Simulate a crash AFTER the side effect but BEFORE the durable ack.
        if self.fault_injector is not None:
            self.fault_injector(step_id, attempt)

        successors = [s.id for s in definition.steps if step_id in s.depends_on]
        self.history.commit_step(run_id, step_id, result, successors)

    def _aggregate_result(self, run_id: str) -> dict:
        """Collect per-step results from the completed events for the final record."""
        out: dict[str, dict] = {}
        for ev in self.history.events(run_id):
            if ev["type"] == ACTIVITY_COMPLETED:
                import json

                out[ev["step_id"]] = json.loads(ev["payload"])
        return out
