"""Lazy Anthropic client singleton.

Returns None when ANTHROPIC_API_KEY is not set so the rest of the app
can run in mock mode without a real key.
"""

from __future__ import annotations

import os

_client = None

MODEL = "claude-sonnet-4-6"


def get_client():
    """Return the shared Anthropic client, or None if no API key is configured."""
    global _client
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    if _client is None:
        import anthropic
        _client = anthropic.Anthropic(api_key=api_key)
    return _client
