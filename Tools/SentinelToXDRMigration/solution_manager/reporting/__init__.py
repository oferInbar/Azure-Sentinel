"""Migration and qualification evidence projection, HTML dashboards, and reviewer exports."""
from __future__ import annotations

from solution_manager.reporting.decision_manifest import (
    ALLOWED_DECISION_SCOPES,
    DECISION_MANIFEST_SCHEMA_VERSION,
    DEFAULT_DECISION_MANIFEST_FILENAME,
    build_sanitized_decision_manifest,
    sanitize_decision_text,
    verify_sanitized_decision_manifest,
    write_sanitized_decision_manifest,
)

__all__ = [
    "ALLOWED_DECISION_SCOPES",
    "DECISION_MANIFEST_SCHEMA_VERSION",
    "DEFAULT_DECISION_MANIFEST_FILENAME",
    "build_sanitized_decision_manifest",
    "sanitize_decision_text",
    "verify_sanitized_decision_manifest",
    "write_sanitized_decision_manifest",
]

