"""SOAR playbooks expressed as workflow DAGs, built from alerts."""

from app.playbooks.library import build_playbook, playbook_for_alert

__all__ = ["build_playbook", "playbook_for_alert"]
