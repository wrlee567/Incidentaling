"""Hybrid (push + pull) telemetry ingestion."""

from app.ingestion.buffer import PullBuffer

__all__ = ["PullBuffer"]
