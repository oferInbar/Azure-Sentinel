from __future__ import annotations

from typing import Any

from .durations import iso_duration

TRIGGER_OPERATORS = {
    "gt": "GreaterThan",
    "lt": "LessThan",
    "eq": "Equal",
    "ne": "NotEqual",
}


def _duration(value: Any, field: str) -> str:
    duration, warning = iso_duration(value)
    if warning:
        raise ValueError(f"{field}: {warning}")
    return duration


def analytic_rule_payload(document: dict[str, Any]) -> dict[str, Any]:
    if str(document.get("kind") or "").lower() != "scheduled":
        raise ValueError("only Scheduled analytic rules can be deployed")
    required = ("id", "name", "query", "severity", "queryFrequency", "queryPeriod")
    missing = [field for field in required if not document.get(field)]
    if missing:
        raise ValueError(f"analytic rule is missing: {', '.join(missing)}")

    trigger = str(document.get("triggerOperator") or "gt").lower()
    if trigger not in TRIGGER_OPERATORS:
        raise ValueError(f"unsupported triggerOperator: {trigger}")

    properties: dict[str, Any] = {
        "displayName": str(document["name"]),
        "description": str(document.get("description") or ""),
        "severity": str(document["severity"]),
        "enabled": False,
        "query": str(document["query"]),
        "queryFrequency": _duration(document["queryFrequency"], "queryFrequency"),
        "queryPeriod": _duration(document["queryPeriod"], "queryPeriod"),
        "triggerOperator": TRIGGER_OPERATORS[trigger],
        "triggerThreshold": int(document.get("triggerThreshold") or 0),
        "suppressionDuration": _duration(
            document.get("suppressionDuration") or "5h", "suppressionDuration"
        ),
        "suppressionEnabled": bool(document.get("suppressionEnabled", False)),
        "eventGroupingSettings": document.get("eventGroupingSettings")
        or {"aggregationKind": "SingleAlert"},
        "alertRuleTemplateName": str(document["id"]),
        "templateVersion": str(document.get("version") or ""),
    }
    for source, target in (
        ("tactics", "tactics"),
        ("relevantTechniques", "techniques"),
        ("entityMappings", "entityMappings"),
        ("customDetails", "customDetails"),
        ("alertDetailsOverride", "alertDetailsOverride"),
        ("incidentConfiguration", "incidentConfiguration"),
    ):
        value = document.get(source)
        if value is not None:
            properties[target] = value
    return {"kind": "Scheduled", "properties": properties}
