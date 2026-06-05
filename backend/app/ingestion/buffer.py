"""Server-side model of the *pull* ingestion path.

In a real deployment, EDR agents spool routine, lower-severity logs to a local
buffer and the central SIEM *pulls* them on its own schedule. The server controls
the rate, so it can batch, apply backpressure, and avoid the "thundering herd"
that a pure push model suffers during a broad incident.

We model the agent spool as a bounded in-memory queue. ``offer`` is what an agent
appends; ``drain`` is what the server's poller pulls in controlled batches.
"""

from __future__ import annotations

from collections import deque

from app.models import TelemetryEnvelope


class PullBuffer:
    """A bounded FIFO spool drained in batches by the server."""

    def __init__(self, capacity: int = 100_000) -> None:
        self.capacity = capacity
        self._q: deque[TelemetryEnvelope] = deque()
        self.dropped = 0  # backpressure signal: spool overflow drops oldest

    def offer(self, env: TelemetryEnvelope) -> bool:
        """Append one envelope. Returns False if a drop occurred (overflow)."""
        if len(self._q) >= self.capacity:
            self._q.popleft()
            self.dropped += 1
            self._q.append(env)
            return False
        self._q.append(env)
        return True

    def drain(self, max_batch: int) -> list[TelemetryEnvelope]:
        """Pull up to ``max_batch`` envelopes — the server-controlled poll."""
        batch: list[TelemetryEnvelope] = []
        for _ in range(min(max_batch, len(self._q))):
            batch.append(self._q.popleft())
        return batch

    @property
    def depth(self) -> int:
        return len(self._q)
