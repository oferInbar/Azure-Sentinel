from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from sentinel_xdr_migration.analytic_deployment import (
    analytic_rule_payload,
    deploy_analytic_rules,
)


def document() -> dict:
    return {
        "id": "a7ce6135-9d55-4f14-b058-adc2e920a4fb",
        "name": "Test analytic rule",
        "description": "Test",
        "severity": "Medium",
        "queryFrequency": "1h",
        "queryPeriod": "2h",
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "query": "Cloudflare | take 1",
        "tactics": ["InitialAccess"],
        "relevantTechniques": ["T1190"],
        "entityMappings": [
            {
                "entityType": "IP",
                "fieldMappings": [
                    {"identifier": "Address", "columnName": "SrcIpAddr"}
                ],
            }
        ],
        "version": "1.0.1",
        "kind": "Scheduled",
    }


class AnalyticDeploymentTests(unittest.TestCase):
    def test_package_import_graph_has_no_analytic_or_parity_cycle(self) -> None:
        package = Path(__file__).resolve().parents[1] / "sentinel_xdr_migration"
        modules = {path.stem: path for path in package.glob("*.py")}
        graph = {name: set() for name in modules}
        for name, path in modules.items():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level != 1:
                    continue
                if node.module and node.module.split(".")[0] in modules:
                    graph[name].add(node.module.split(".")[0])
                elif node.module is None:
                    graph[name].update(
                        alias.name for alias in node.names if alias.name in modules
                    )

        for root in ("analytic_deployment", "alert_parity"):
            pending = [root]
            visited = {root}
            while pending:
                module = pending.pop()
                for dependency in graph[module]:
                    if dependency == root:
                        self.fail(f"import cycle returns to {root} through {module}")
                    if dependency not in visited:
                        visited.add(dependency)
                        pending.append(dependency)

    def test_analytic_and_parity_imports_work_in_either_order(self) -> None:
        package_root = Path(__file__).resolve().parents[1]
        for imports in (
            "import sentinel_xdr_migration.analytic_deployment as analytic_deployment\n"
            "import sentinel_xdr_migration.alert_parity as alert_parity\n"
            "import sentinel_xdr_migration.analytic_rule as analytic_rule\n"
            "import sentinel_xdr_migration.arm_client as arm_client\n"
            "import sentinel_xdr_migration.deployment_planning as deployment_planning\n"
            "assert analytic_deployment._arm_request is arm_client._arm_request\n"
            "assert alert_parity._arm_request is arm_client._arm_request\n"
            "assert (\n"
            "    analytic_deployment.analytic_rule_payload\n"
            "    is analytic_rule.analytic_rule_payload\n"
            ")\n"
            "assert (\n"
            "    deployment_planning.analytic_rule_payload\n"
            "    is analytic_rule.analytic_rule_payload\n"
            ")",
            "import sentinel_xdr_migration.deployment_planning as deployment_planning\n"
            "import sentinel_xdr_migration.alert_parity as alert_parity\n"
            "import sentinel_xdr_migration.analytic_deployment as analytic_deployment\n"
            "import sentinel_xdr_migration.analytic_rule as analytic_rule\n"
            "import sentinel_xdr_migration.arm_client as arm_client\n"
            "assert analytic_deployment._arm_request is arm_client._arm_request\n"
            "assert alert_parity._arm_request is arm_client._arm_request\n"
            "assert (\n"
            "    analytic_deployment.analytic_rule_payload\n"
            "    is analytic_rule.analytic_rule_payload\n"
            ")\n"
            "assert (\n"
            "    deployment_planning.analytic_rule_payload\n"
            "    is analytic_rule.analytic_rule_payload\n"
            ")",
        ):
            with self.subTest(imports=imports):
                subprocess.run(
                    [sys.executable, "-c", imports],
                    cwd=package_root,
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_payload_is_disabled_and_preserves_source_metadata(self) -> None:
        payload = analytic_rule_payload(document())

        self.assertFalse(payload["properties"]["enabled"])
        self.assertEqual(payload["properties"]["queryFrequency"], "PT1H")
        self.assertEqual(payload["properties"]["queryPeriod"], "PT2H")
        self.assertEqual(payload["properties"]["triggerOperator"], "GreaterThan")
        self.assertEqual(
            payload["properties"]["alertRuleTemplateName"], document()["id"]
        )

    @mock.patch(
        "sentinel_xdr_migration.analytic_deployment._arm_token",
        return_value="token",
    )
    @mock.patch(
        "sentinel_xdr_migration.analytic_deployment.require_locked_target",
        return_value={
            "tenantId": "39768270-33ce-4b90-a1a6-e0caeb3ba0ab",
            "subscriptionId": "42382e39-f157-46d1-a931-b8cfd779ece5",
            "workspaceResourceId": (
                "/subscriptions/42382e39-f157-46d1-a931-b8cfd779ece5/"
                "resourceGroups/rg/providers/Microsoft.OperationalInsights/"
                "workspaces/ws"
            ),
            "workspaceCustomerId": "756386d8-e2d4-4f09-905a-74b24313721f",
        },
    )
    @mock.patch("sentinel_xdr_migration.analytic_deployment._arm_request")
    def test_deploy_upserts_rule_disabled(
        self, request: mock.Mock, _target: mock.Mock, _token: mock.Mock
    ) -> None:
        request.return_value = (
            201,
            {"properties": {"enabled": False}},
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Analytic Rules"
            source.mkdir()
            (source / "rule.yaml").write_text(
                yaml.safe_dump(document()), encoding="utf-8"
            )

            result = deploy_analytic_rules(
                root,
                workspace_resource_id="/subscriptions/sub/resourceGroups/rg"
                "/providers/Microsoft.OperationalInsights/workspaces/ws",
            )

        self.assertEqual(result["succeeded"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(request.call_args.args[0], "PUT")
        self.assertFalse(request.call_args.args[3]["properties"]["enabled"])


if __name__ == "__main__":
    unittest.main()
