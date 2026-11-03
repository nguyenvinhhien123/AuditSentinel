"""Persistent, isolated work sessions for AuditSentinel."""

from src.sessions.manager import (
    LEGACY_SESSION_ID,
    SessionContext,
    SessionManager,
)

__all__ = ["LEGACY_SESSION_ID", "SessionContext", "SessionManager"]
