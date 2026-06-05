"""Dependency wiring for FastAPI routes."""

from __future__ import annotations

from fastapi import Request

from app.state import AppState


def get_state(request: Request) -> AppState:
    """Return the per-app :class:`AppState` stored on ``app.state``."""
    return request.app.state.app_state
