"""Directed-acyclic-graph workflow definitions for SOAR playbooks.

A playbook is a DAG of activities with explicit dependencies. The whole DAG runs inside
a *single* parent workflow (the engine loops over it) — we deliberately avoid the common
anti-pattern of spawning a separate workflow per step, which would exhaust the engine.

The model validates that step ids are unique, dependencies exist, and the graph is
acyclic, then exposes execution *waves*: each wave is a set of steps whose dependencies
are all satisfied and which may therefore run in parallel on separate workers.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    activity: str = Field(..., description="Name registered in the activity registry.")
    params: dict = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)


class WorkflowDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    steps: list[WorkflowStep]

    @model_validator(mode="after")
    def _validate_graph(self) -> "WorkflowDefinition":
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate step ids")
        idset = set(ids)
        for s in self.steps:
            for dep in s.depends_on:
                if dep not in idset:
                    raise ValueError(f"step {s.id!r} depends on unknown step {dep!r}")
        # Cycle detection via Kahn's algorithm (also yields a valid topo order).
        self._topo_order()  # raises on cycle
        return self

    def _topo_order(self) -> list[str]:
        indeg = {s.id: len(s.depends_on) for s in self.steps}
        adj: dict[str, list[str]] = {s.id: [] for s in self.steps}
        for s in self.steps:
            for dep in s.depends_on:
                adj[dep].append(s.id)
        ready = [sid for sid, d in indeg.items() if d == 0]
        order: list[str] = []
        while ready:
            ready.sort()  # deterministic
            sid = ready.pop(0)
            order.append(sid)
            for nxt in adj[sid]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    ready.append(nxt)
        if len(order) != len(self.steps):
            raise ValueError("workflow graph contains a cycle")
        return order

    def step(self, step_id: str) -> WorkflowStep:
        return next(s for s in self.steps if s.id == step_id)

    def ready_steps(self, completed: set[str]) -> list[str]:
        """Steps not yet completed whose dependencies are all completed.

        These can be dispatched concurrently; the engine picks them up each loop.
        """
        out = []
        for s in self.steps:
            if s.id in completed:
                continue
            if all(dep in completed for dep in s.depends_on):
                out.append(s.id)
        return out
