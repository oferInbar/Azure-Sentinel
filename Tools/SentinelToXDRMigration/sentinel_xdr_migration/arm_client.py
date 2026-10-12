from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .graph_client_config import azure_cli_credential
from .onboarding import _state_dir

ARM_SCOPE = "https://management.azure.com/.default"
SENTINEL_ALERT_RULE_API_VERSION = "2024-03-01"


def _arm_token(state_dir: str | Path | None = None) -> str:
    return azure_cli_credential(
        state_root=_state_dir(state_dir)
    ).get_token(ARM_SCOPE).token


def _arm_request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            content = response.read().decode("utf-8")
            return response.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as exc:
        content = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = {"error": {"message": content[:4000]}}
        return exc.code, parsed


def _sentinel_rule_url(workspace_resource_id: str, rule_id: str) -> str:
    workspace = workspace_resource_id.rstrip("/")
    encoded_id = urllib.parse.quote(rule_id, safe="")
    return (
        "https://management.azure.com"
        f"{workspace}/providers/Microsoft.SecurityInsights/alertRules/{encoded_id}"
        f"?api-version={SENTINEL_ALERT_RULE_API_VERSION}"
    )
