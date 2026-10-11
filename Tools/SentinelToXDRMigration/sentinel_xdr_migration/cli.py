from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .converter import (
    configure_logging,
    convert_solution,
    inspect_solution,
    runtime_validation_plan,
    validate_solution,
)
from .artifacts import migrate_reports, select_run, reset_run_selection, list_runs
from .evidence import export_evidence
from .budget import (
    DEFAULT_POLICY,
    budget_summary,
    extend_budget,
    reconcile_legacy_usage,
    reconcile_pending_operation,
    set_observation_deadline,
)
from .onboarding import configure_workspace, doctor, setup
from .deployment import deploy_solution, setup_deployment_authentication
from .deployment_planning import persist_deployment_plan, record_planning_consent
from .graph_readiness import preflight_deployment
from .analytic_deployment import deploy_analytic_rules
from .alert_parity import (
    abort_alert_parity,
    complete_alert_parity,
    start_alert_parity,
    start_alert_parity_batch,
)
from .runtime import (
    record_runtime_validation,
    validate_advanced_hunting,
    validate_sentinel_sdk,
)
from .solution_report import build_solution_report
from .target_context import diagnose_target, repair_target, require_locked_target
from .target_config import resolve_qualification_target
from .workflow import (
    STAGES,
    WORKFLOW_PROFILES,
    complete_workflow_stage,
    initialize_workflow,
    next_workflow_stage,
    read_authoring_contract,
    package_workflow_v3_1,
    plan_new_package_release,
    refresh_yolo_authoring,
    run_yolo_authoring,
    start_workflow_stage,
    workflow_status,
)

SUPPORTED_PYTHON_MIN = (3, 11)
SUPPORTED_PYTHON_MAX_EXCLUSIVE = (3, 13)


def _print(value: dict) -> None:
    print(json.dumps(value, indent=2))


def _key_values(values: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values or []:
        key, separator, item = value.partition("=")
        if not separator or not key.strip() or not item.strip():
            raise ValueError(f"expected NAME=VALUE, received: {value}")
        if key in result:
            raise ValueError(f"duplicate artifact name: {key}")
        result[key] = item
    return result


def main(argv: list[str] | None = None) -> int:
    if not (
        SUPPORTED_PYTHON_MIN
        <= sys.version_info[:2]
        < SUPPORTED_PYTHON_MAX_EXCLUSIVE
    ):
        print(
            "sentinel-xdr-migration requires Python 3.11 or 3.12. "
            "Install or select a supported interpreter; do not modify toolkit "
            "source to compensate for the local Python version.",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(
        description="Convert Microsoft Sentinel analytic rules into XDR Custom Detection YAML."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    migration = subparsers.add_parser("migrate-reports", help="Plan a non-destructive copy of legacy reports into solution Logs.")
    migration.add_argument("--solution", required=True)
    migration.add_argument("--apply", action="store_true", help="Copy after reviewing the dry-run; originals are preserved.")
    evidence = subparsers.add_parser("export-evidence", help="Explicitly export immutable, curated local PR evidence; no cloud writes.")
    evidence.add_argument("--solution", required=True)
    evidence.add_argument(
        "--include-authoring-contract",
        action="store_true",
        help="Include the selected run's validated, immutable YOLO contract projection.",
    )
    for command in (
        "inspect",
        "convert",
        "validate",
        "validation-plan",
        "validate-advanced-hunting",
        "validate-sentinel-sdk",
    ):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--solution", required=True)
        if command == "convert":
            subparser.add_argument("--overwrite", action="store_true")
            subparser.add_argument("--config")
            subparser.add_argument(
                "--rule-id", action="append",
                help="Convert exactly one source template GUID; does not establish solution readiness.",
            )
        if command == "validate-advanced-hunting":
            subparser.add_argument(
                "--provider-gap-evidence",
                help="JSON evidence for a complete Graph fallback after a Triage MCP provider failure.",
            )
        if command == "validate-sentinel-sdk":
            subparser.add_argument(
                "--request-timeout-seconds",
                type=int,
                default=90,
                help="Maximum server/network timeout per Logs query (1-600 seconds).",
            )
            subparser.add_argument(
                "--family-timeout-seconds",
                type=int,
                default=1800,
                help="Maximum elapsed budget for this complete source-query family (1-21600 seconds).",
            )
            subparser.add_argument(
                "--provider-gap-evidence",
                help="JSON evidence for the complete Azure Monitor SDK fallback after a Triage MCP provider failure.",
            )
    setup_parser = subparsers.add_parser(
        "setup", help="Initialize the toolkit and optionally launch guided authentication."
    )
    setup_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Inspect and initialize without opening authentication prompts.",
    )
    setup_parser.add_argument("--tenant-id")
    setup_parser.add_argument("--workspace-id")
    setup_parser.add_argument(
        "--hunting-client-id",
        help="Public delegated Graph client ID for Advanced Hunting; the built-in client remains the default.",
    )
    setup_parser.add_argument(
        "--azure-config-dir",
        help="Explicitly select and persist an isolated Azure CLI profile for this target.",
    )
    setup_parser.add_argument(
        "--hunting-auth-method",
        choices=["device-code", "browser"],
        default="device-code",
        help="Interactive authentication method for Microsoft Graph.",
    )
    setup_parser.add_argument("--skip-sentinel-auth", action="store_true")
    setup_parser.add_argument("--skip-hunting-auth", action="store_true")
    doctor_parser = subparsers.add_parser(
        "doctor", help="Report setup and runtime readiness."
    )
    doctor_parser.add_argument(
        "--solution",
        help="Also inspect this solution's local .env Qualification target.",
    )
    workspace_config = subparsers.add_parser(
        "configure-workspace",
        help="Persist one approved workspace for reuse across solution workflows.",
    )
    workspace_config.add_argument("--workspace-resource-id", required=True)
    workspace_config.add_argument("--workspace-customer-id")
    workspace_config.add_argument("--tenant-id")
    workspace_config.add_argument("--subscription-id")
    target_diagnostics = subparsers.add_parser(
        "qualification-diagnose",
        help="Diagnose the one locked Qualification target without broad discovery.",
    )
    target_diagnostics.add_argument("--solution", required=True)
    target_repair = subparsers.add_parser(
        "qualification-repair-target",
        help="Apply the exact target correction proposed by current diagnostics.",
    )
    target_repair.add_argument("--solution", required=True)
    target_repair.add_argument("--approve-target-update", action="store_true")
    deployment_setup = subparsers.add_parser(
        "setup-deployment",
        help="Authenticate for Microsoft Graph Custom Detection deployment.",
    )
    deployment_setup.add_argument("--tenant-id")
    deployment_setup.add_argument("--solution", required=True)
    deployment_setup.add_argument(
        "--custom-detection-client-id",
        help="Public delegated Graph client ID for Custom Detection; the built-in client remains the default.",
    )
    deployment_setup.add_argument(
        "--azure-config-dir",
        help="Explicitly select and persist an isolated Azure CLI profile for this target.",
    )
    app_registration_auth = subparsers.add_parser(
        "setup-app-registration-auth",
        help="Explicitly authenticate with the least-privilege app-registration bootstrap scope.",
    )
    app_registration_auth.add_argument("--solution", required=True)
    app_registration_auth.add_argument(
        "--auth-method",
        choices=["device-code", "browser"],
        default="device-code",
    )
    app_registration_auth.add_argument(
        "--bootstrap-client-id",
        help="Existing public Graph client ID already able to request the bootstrap scopes; defaults to the built-in client.",
    )
    app_readback_auth = subparsers.add_parser(
        "setup-app-readback-auth",
        help="Set up the separate browser-only, GET-only delegated app verification credential.",
    )
    app_readback_auth.add_argument("--solution", required=True)
    app_readback_auth.add_argument(
        "--readback-client-id",
        required=True,
        help="Existing separately approved public Graph client ID; never reuses bootstrap or Custom Detection auth.",
    )
    app_readback = subparsers.add_parser(
        "verify-delegated-app-readback",
        help="Read-only reconciliation for the exact approved owned application; performs GET requests only.",
    )
    app_readback.add_argument("--solution", required=True)
    app_readback_scope_diagnostic = subparsers.add_parser(
        "diagnose-app-readback-scopes",
        help="Report required and extra cached readback-token scope names; makes no Microsoft Graph resource requests.",
    )
    app_readback_scope_diagnostic.add_argument("--solution", required=True)
    app_registration_plan = subparsers.add_parser(
        "plan-delegated-app-registration",
        help="Show the exact single-tenant delegated desktop-app plan; performs no cloud calls.",
    )
    app_registration_plan.add_argument("--solution", required=True)
    app_registration_plan.add_argument(
        "--app-display-name",
        help="Exact application display name to bind into the reviewed plan; defaults to the legacy name.",
    )
    app_registration = subparsers.add_parser(
        "register-delegated-app",
        help="Create at most one explicitly approved delegated Graph desktop app; grants no consent.",
    )
    app_registration.add_argument("--solution", required=True)
    app_registration.add_argument(
        "--app-display-name",
        help="Exact application display name bound into the reviewed plan; defaults to the legacy name.",
    )
    app_registration.add_argument("--expected-plan-sha256", required=True)
    app_registration.add_argument(
        "--approve-exact-app-registration",
        action="store_true",
        help="Approve only the application registration bound to the supplied plan hash.",
    )
    deployment_setup.add_argument(
        "--auth-method",
        choices=["azure-cli", "device-code", "browser"],
        default="azure-cli",
    )
    deployment = subparsers.add_parser(
        "deploy",
        help="Create or update generated Custom Detections through Microsoft Graph beta.",
    )
    deployment.add_argument("--solution", required=True)
    deployment_preflight = subparsers.add_parser(
        "preflight-deployment",
        help=(
            "Run local Graph readiness plus independent read-only DCR, ingestion, "
            "query, and deployment permission diagnostics."
        ),
    )
    deployment_preflight.add_argument("--solution", required=True)
    deployment_preflight.add_argument(
        "--auth-method",
        choices=["azure-cli", "device-code", "browser"],
        help=(
            "Use this existing cached credential method only; authentication "
            "is never started by preflight."
        ),
    )
    deployment_plan = subparsers.add_parser(
        "plan-deployment",
        help="Persist a deterministic local Qualification deployment-scope plan; performs no cloud calls.",
    )
    deployment_plan.add_argument("--solution", required=True)
    planning_consent = subparsers.add_parser(
        "review-deployment-plan",
        help="Record or decline component-specific planning consent bound to the current plan hash; authorizes no writes.",
    )
    planning_consent.add_argument("--solution", required=True)
    planning_consent.add_argument("--expected-plan-sha256", required=True)
    planning_consent.add_argument("--actor", required=True)
    planning_consent.add_argument(
        "--approve-component",
        action="append",
        choices=[
            "sentinelAlertRules",
            "xdrCustomDetections",
            "fullPackageAcceptance",
            "mockTelemetryIngestion",
            "fallbackDcr",
            "fallbackDce",
            "customTableCreate",
        ],
        default=[],
    )
    planning_consent.add_argument("--decline", action="store_true")
    planning_consent.add_argument("--reason")
    planning_consent.add_argument("--max-additional-custom-detections", type=int)
    planning_consent.add_argument(
        "--package-flag",
        action="append",
        help="Explicit package selection as NAME=true|false; repeat for every package flag.",
    )
    planning_consent.add_argument(
        "--dce-selected",
        action="store_true",
        help="Explicitly select the conditional DCE component for this plan.",
    )
    analytic_deployment = subparsers.add_parser(
        "deploy-analytic-rules",
        help="Create or update source Sentinel analytic rules through Azure Resource Manager.",
    )
    analytic_deployment.add_argument("--solution", required=True)
    analytic_deployment.add_argument("--workspace-resource-id")
    parity_start = subparsers.add_parser(
        "start-alert-parity",
        help="Enable disabled AR/CD pairs, ingest a marked mock payload, and emit capture queries.",
    )
    parity_start.add_argument("--solution", required=True)
    parity_start.add_argument("--workspace-resource-id")
    parity_start.add_argument("--contract", required=True)
    parity_start.add_argument("--payload", required=True)
    parity_start.add_argument("--scenario-marker", required=True)
    parity_start.add_argument(
        "--expected-match-key",
        action="append",
        dest="expected_match_keys",
        help="Exact malicious alert match key; repeat for multiple expected alerts. Defaults to the scenario marker.",
    )
    parity_start.add_argument(
        "--detection",
        action="append",
        dest="detections",
        help="Detection filename or stem to validate; repeat to select multiple.",
    )
    parity_complete = subparsers.add_parser(
        "complete-alert-parity",
        help="Compare normalized AR/CD alerts strictly and disable every test rule.",
    )
    parity_complete.add_argument("--solution", required=True)
    parity_complete.add_argument("--results", required=True)
    parity_batch = subparsers.add_parser(
        "start-alert-parity-batch",
        help="Enable all reviewed AR/CD pairs and ingest one fixture per detection.",
    )
    parity_batch.add_argument("--solution", required=True)
    parity_batch.add_argument("--workspace-resource-id")
    parity_batch.add_argument("--plan", required=True)
    parity_abort = subparsers.add_parser(
        "abort-alert-parity",
        help="Disable every rule associated with an active parity run.",
    )
    parity_abort.add_argument("--solution", required=True)
    report_parser = subparsers.add_parser(
        "solution-report",
        help="Build one consolidated per-rule AR/CD migration report.",
    )
    report_parser.add_argument("--solution", required=True)
    report_parser.add_argument(
        "--ingestion-report",
        action="append",
        dest="ingestion_reports",
        help="Ingestion report JSON to include; repeat for multiple streams.",
    )
    record_parser = subparsers.add_parser(
        "record-runtime-validation",
        help="Normalize and report results produced by an external runtime provider.",
    )
    record_parser.add_argument("--solution", required=True)
    record_parser.add_argument(
        "--provider",
        required=True,
        choices=["triage-mcp", "azure-monitor-sdk", "log-analytics-cli"],
    )
    record_parser.add_argument("--results", required=True)
    record_parser.add_argument(
        "--provider-gap-evidence",
        help="JSON evidence for a complete Log Analytics fallback after a Triage MCP provider failure.",
    )
    package_v3_1 = subparsers.add_parser(
        "package-v3-1",
        help="Package with V3.1; initialized YOLO runs enforce workflow and fresh-evidence gates.",
    )
    package_v3_1.add_argument("--solution", required=True)
    package_v3_1.add_argument(
        "--toolkit-root",
        help=(
            "Repository root containing the V3.1 packaging toolkit. Defaults to the "
            "solution's repository root."
        ),
    )
    package_v3_1.add_argument(
        "--version-bump",
        required=True,
        choices=["none", "patch", "minor", "major"],
    )
    package_release = subparsers.add_parser(
        "workflow-plan-package-release",
        help="Explicitly select a new V3.1 release action for changed package inputs.",
    )
    package_release.add_argument("--solution", required=True)
    package_release.add_argument("--version-bump", required=True, choices=["patch", "minor", "major"])
    package_release.add_argument(
        "--expected-package-input-sha256",
        required=True,
        help="Exact current package-input SHA-256 reported by workflow-status.",
    )
    workflow_init = subparsers.add_parser(
        "workflow-init",
        help="Create or resume the gated end-to-end migration workflow state.",
    )
    workflow_init.add_argument("--solution", required=True)
    workflow_init.add_argument("--tenant-id")
    workflow_init.add_argument("--subscription-id")
    workflow_init.add_argument("--workspace-resource-id")
    workflow_init.add_argument("--workspace-customer-id")
    workflow_init.add_argument(
        "--confirm-configured-target",
        action="store_true",
        help="Confirm the tenant/workspace shown by doctor for a new Qualification run.",
    )
    workflow_init.add_argument(
        "--version-bump",
        choices=["none", "patch", "minor", "major"],
    )
    workflow_init.add_argument(
        "--workflow-profile",
        required=True,
        choices=WORKFLOW_PROFILES,
        help="Explicitly select authoring or qualification before initialization.",
    )
    workflow_init.add_argument(
        "--yolo",
        action="store_true",
        help="Opt into full-inventory, resumable local authoring orchestration for a new run.",
    )
    workflow_init.add_argument(
        "--campaign-id",
        help="Explicit durable budget campaign identity; required for every new YOLO campaign.",
    )
    workflow_yolo = subparsers.add_parser(
        "workflow-yolo",
        help="Run the existing local discovery, full-solution converter, and structural validator under an initialized YOLO contract.",
    )
    workflow_yolo.add_argument("--solution", required=True)
    workflow_yolo_refresh = subparsers.add_parser(
        "workflow-yolo-refresh",
        help="Import current hash-bound provider reports without rerunning conversion or validation.",
    )
    workflow_yolo_refresh.add_argument("--solution", required=True)
    workflow_status_parser = subparsers.add_parser(
        "workflow-status",
        help="Show the persisted end-to-end migration workflow state.",
    )
    workflow_status_parser.add_argument("--solution", required=True)
    workflow_next = subparsers.add_parser(
        "workflow-next",
        help="Return the next stage whose dependencies have passed.",
    )
    workflow_next.add_argument("--solution", required=True)
    workflow_start = subparsers.add_parser(
        "workflow-start-stage",
        help="Start or retry one gated workflow stage.",
    )
    workflow_start.add_argument("--solution", required=True)
    workflow_start.add_argument("--stage", required=True, choices=STAGES)
    workflow_complete = subparsers.add_parser(
        "workflow-complete-stage",
        help="Persist the terminal result and evidence for a running stage.",
    )
    workflow_complete.add_argument("--solution", required=True)
    workflow_complete.add_argument("--stage", required=True, choices=STAGES)
    workflow_complete.add_argument(
        "--status",
        required=True,
        choices=["passed", "failed", "blocked"],
    )
    workflow_complete.add_argument("--message")
    workflow_complete.add_argument(
        "--artifact",
        action="append",
        help="Stage artifact as NAME=VALUE; repeat for multiple artifacts.",
    )
    workflow_complete.add_argument(
        "--evidence",
        action="append",
        help="Evidence path or reference; repeat for multiple values.",
    )
    budget_status = subparsers.add_parser(
        "workflow-budget",
        help="Show configured ceilings, measured receipts, unknown usage, and remaining campaign allowance.",
    )
    budget_status.add_argument("--solution", required=True)
    budget_status.add_argument("--campaign-id", required=True)
    budget_extend = subparsers.add_parser(
        "workflow-budget-extend",
        help="Raise one campaign ceiling with an append-only owner-scope audit receipt.",
    )
    budget_extend.add_argument("--solution", required=True)
    budget_extend.add_argument("--campaign-id", required=True)
    budget_extend.add_argument("--dimension", required=True, choices=sorted(DEFAULT_POLICY))
    budget_extend.add_argument("--new-limit", required=True, type=float)
    budget_extend.add_argument("--actor", required=True)
    budget_extend.add_argument("--reason", required=True)
    budget_extend.add_argument("--reference", required=True)
    budget_reconcile = subparsers.add_parser(
        "workflow-budget-reconcile",
        help="Reconcile one interrupted operation using its authoritative measured outcome.",
    )
    budget_reconcile.add_argument("--solution", required=True)
    budget_reconcile.add_argument("--campaign-id", required=True)
    budget_reconcile.add_argument("--operation-id", required=True)
    budget_reconcile.add_argument(
        "--status", required=True, choices=["passed", "failed", "cancelled", "unknown"],
    )
    budget_reconcile.add_argument("--elapsed-seconds", required=True, type=float)
    budget_reconcile.add_argument("--actor", required=True)
    budget_reconcile.add_argument("--reason", required=True)
    budget_reconcile.add_argument("--reference", required=True)
    budget_legacy = subparsers.add_parser(
        "workflow-budget-reconcile-legacy",
        help="Record an owner-reviewed baseline for a pre-budget run; no history is reconstructed.",
    )
    budget_legacy.add_argument("--solution", required=True)
    budget_legacy.add_argument("--campaign-id", required=True)
    budget_legacy.add_argument("--baseline", required=True, help="JSON file containing every measured legacy dimension.")
    budget_legacy.add_argument("--actor", required=True)
    budget_legacy.add_argument("--reason", required=True)
    budget_legacy.add_argument("--reference", required=True)
    budget_deadline = subparsers.add_parser(
        "workflow-budget-deadline",
        help="Persist the approved schedule-aware alert-observation deadline for one test.",
    )
    budget_deadline.add_argument("--solution", required=True)
    budget_deadline.add_argument("--campaign-id", required=True)
    budget_deadline.add_argument("--test-id", required=True)
    budget_deadline.add_argument("--deadline-at", required=True)
    budget_deadline.add_argument("--approval-reference", required=True)
    budget_deadline.add_argument("--actor", required=True)
    budget_deadline.add_argument("--reason", required=True)

    runs_parser = subparsers.add_parser("workflow-runs", help="List run IDs without selecting or modifying state.")
    runs_parser.add_argument("--solution", required=True)
    for subparser in subparsers.choices.values():
        if any(action.dest == "solution" for action in subparser._actions):
            subparser.add_argument("--run-id", help="Select an existing run; required when multiple runs exist.")
    for action in subparsers.choices["workflow-plan-package-release"]._actions:
        if action.dest == "run_id":
            action.required = True
            action.help = "Select the exact existing workflow run to update."
            break
    for action in subparsers.choices["diagnose-app-readback-scopes"]._actions:
        if action.dest == "run_id":
            action.required = True
            action.help = "Select the exact approved Cisco qualification run."
            break
    subparsers.choices["workflow-init"].add_argument(
        "--new-run", action="store_true", help="Create an isolated new workflow instead of resuming."
    )
    args = parser.parse_args(argv)
    if args.command == "convert" and args.rule_id and len(args.rule_id) != 1:
        parser.error("--rule-id accepts exactly one GUID; repeated selectors are not supported")
    selection = None
    try:
        if getattr(args, "solution", None):
            selection = select_run(args.solution, args.run_id)
        # Read-only status and migration planning must not initialize or change artifacts.
        if args.command not in {"migrate-reports", "workflow-status", "workflow-next", "workflow-init", "workflow-runs", "export-evidence", "preflight-deployment", "plan-deployment", "review-deployment-plan"} and not (
            args.command == "convert" and args.rule_id
        ):
            configure_logging(getattr(args, "solution", None))
        if args.command == "workflow-runs":
            result = {"runs": list_runs(args.solution)}
        elif args.command == "export-evidence":
            if args.include_authoring_contract and not args.run_id:
                raise ValueError(
                    "--include-authoring-contract requires an explicit --run-id"
                )
            authoring_contract = (
                read_authoring_contract(args.solution)
                if args.include_authoring_contract else None
            )
            result = export_evidence(
                args.solution,
                authoring_contract=authoring_contract,
            )
        elif args.command == "migrate-reports":
            result = migrate_reports(args.solution, apply=args.apply)
        elif args.command == "setup":
            result = setup(
                interactive=not args.non_interactive,
                tenant_id=args.tenant_id,
                workspace_id=args.workspace_id,
                skip_sentinel_auth=args.skip_sentinel_auth,
                skip_hunting_auth=args.skip_hunting_auth,
                hunting_auth_method=args.hunting_auth_method,
                hunting_client_id=args.hunting_client_id,
                azure_config_dir=args.azure_config_dir,
            )
        elif args.command == "doctor":
            result = doctor(solution=args.solution)
        elif args.command == "configure-workspace":
            result = configure_workspace(
                args.workspace_resource_id,
                workspace_customer_id=args.workspace_customer_id,
                tenant_id=args.tenant_id,
                subscription_id=args.subscription_id,
            )
        elif args.command == "qualification-diagnose":
            result = diagnose_target(args.solution)
        elif args.command == "qualification-repair-target":
            result = repair_target(
                args.solution,
                approve_target_update=args.approve_target_update,
            )
        elif args.command == "setup-deployment":
            target = require_locked_target(
                args.solution,
                tenant_id=args.tenant_id,
            )
            result = setup_deployment_authentication(
                tenant_id=target["tenantId"],
                auth_method=args.auth_method,
                graph_client_id=args.custom_detection_client_id,
                azure_config_dir=args.azure_config_dir,
            )
        elif args.command == "setup-app-registration-auth":
            target = require_locked_target(args.solution, materialize_missing=False)
            from .delegated_app_registration import (
                setup_app_registration_authentication,
            )

            result = setup_app_registration_authentication(
                tenant_id=target["tenantId"],
                auth_method=args.auth_method,
                bootstrap_client_id=args.bootstrap_client_id,
            )
        elif args.command == "setup-app-readback-auth":
            target = require_locked_target(args.solution, materialize_missing=False)
            from .delegated_app_registration import (
                setup_app_readback_authentication,
            )

            result = setup_app_readback_authentication(
                tenant_id=target["tenantId"],
                readback_client_id=args.readback_client_id,
            )
        elif args.command == "verify-delegated-app-readback":
            from .delegated_app_registration import verify_delegated_app_readback

            result = verify_delegated_app_readback(args.solution)
        elif args.command == "diagnose-app-readback-scopes":
            from .delegated_app_registration import diagnose_app_readback_scopes

            result = diagnose_app_readback_scopes(
                args.solution,
                run_id=args.run_id,
            )
        elif args.command == "plan-delegated-app-registration":
            from .delegated_app_registration import plan_delegated_app_registration

            result = plan_delegated_app_registration(
                args.solution,
                app_display_name=args.app_display_name,
            )
        elif args.command == "register-delegated-app":
            from .delegated_app_registration import register_delegated_app

            result = register_delegated_app(
                args.solution,
                expected_plan_sha256=args.expected_plan_sha256,
                approve_exact_app_registration=args.approve_exact_app_registration,
                app_display_name=args.app_display_name,
            )
        elif args.command == "deploy":
            result = deploy_solution(args.solution)
        elif args.command == "preflight-deployment":
            result = preflight_deployment(
                args.solution,
                auth_method=args.auth_method,
            )
        elif args.command == "plan-deployment":
            result = persist_deployment_plan(args.solution)
        elif args.command == "review-deployment-plan":
            package_flags: dict[str, bool] = {}
            for name, value in _key_values(args.package_flag).items():
                if value.casefold() not in {"true", "false"}:
                    raise ValueError("--package-flag values must be true or false")
                package_flags[name] = value.casefold() == "true"
            result = record_planning_consent(
                args.solution,
                expected_plan_sha256=args.expected_plan_sha256,
                actor=args.actor,
                approved_components=args.approve_component,
                declined=args.decline,
                reason=args.reason,
                max_additional_custom_detections=args.max_additional_custom_detections,
                package_flags=package_flags,
                dce_selected=args.dce_selected,
            )
        elif args.command == "deploy-analytic-rules":
            result = deploy_analytic_rules(
                args.solution,
                workspace_resource_id=args.workspace_resource_id,
            )
        elif args.command == "start-alert-parity":
            result = start_alert_parity(
                args.solution,
                workspace_resource_id=args.workspace_resource_id,
                contract=args.contract,
                payload=args.payload,
                scenario_marker=args.scenario_marker,
                expected_match_keys=args.expected_match_keys,
                detections=args.detections,
            )
        elif args.command == "complete-alert-parity":
            result = complete_alert_parity(
                args.solution,
                results_path=args.results,
            )
        elif args.command == "start-alert-parity-batch":
            result = start_alert_parity_batch(
                args.solution,
                workspace_resource_id=args.workspace_resource_id,
                plan_path=args.plan,
            )
        elif args.command == "abort-alert-parity":
            result = abort_alert_parity(args.solution)
        elif args.command == "solution-report":
            result = build_solution_report(
                args.solution,
                ingestion_reports=args.ingestion_reports,
            )
        elif args.command == "package-v3-1":
            try:
                current_workflow = workflow_status(args.solution)
            except ValueError as exc:
                if "workflow state does not exist" not in str(exc):
                    raise
                current_workflow = None
            if current_workflow:
                result = package_workflow_v3_1(
                    args.solution,
                    requested_version_bump=args.version_bump,
                    toolkit_root=args.toolkit_root,
                )
            else:
                raise ValueError(
                    "V3.1 package builds require a persisted workflow and campaign budget; "
                    "run workflow-init before packaging"
                )
        elif args.command == "workflow-plan-package-release":
            if not args.run_id:
                raise ValueError(
                    "workflow-plan-package-release requires an explicit --run-id"
                )
            result = plan_new_package_release(
                args.solution,
                version_bump=args.version_bump,
                expected_package_input_sha256=args.expected_package_input_sha256,
            )
        elif args.command == "inspect":
            result = inspect_solution(args.solution)
        elif args.command == "convert":
            result = convert_solution(
                args.solution, overwrite=args.overwrite, config_path=args.config,
                rule_id=args.rule_id[0] if args.rule_id else None,
            )
            if args.rule_id:
                configure_logging(args.solution)
        elif args.command == "validate":
            result = validate_solution(args.solution)
        elif args.command == "validate-advanced-hunting":
            try:
                state = workflow_status(args.solution)
            except ValueError:
                state = None
            target = (
                require_locked_target(args.solution)
                if state
                and state["context"]["workflowProfile"] == "qualification"
                else None
            )
            result = validate_advanced_hunting(
                args.solution,
                tenant_id=target["tenantId"] if target else None,
                provider_gap_evidence=args.provider_gap_evidence,
            )
        elif args.command == "validate-sentinel-sdk":
            target = require_locked_target(args.solution)
            result = validate_sentinel_sdk(
                args.solution,
                target=target,
                request_timeout_seconds=args.request_timeout_seconds,
                family_timeout_seconds=args.family_timeout_seconds,
                provider_gap_evidence=args.provider_gap_evidence,
            )
        elif args.command == "record-runtime-validation":
            result = record_runtime_validation(
                args.solution,
                provider=args.provider,
                results_path=args.results,
                provider_gap_evidence=args.provider_gap_evidence,
            )
        elif args.command == "workflow-init":
            if args.new_run and args.run_id:
                raise ValueError("--new-run and --run-id cannot be combined")
            if (
                args.confirm_configured_target
                and args.workflow_profile != "qualification"
            ):
                raise ValueError(
                    "--confirm-configured-target is only valid for Qualification"
                )
            locked_context = None
            if not args.new_run:
                try:
                    current = workflow_status(args.solution)
                except ValueError as exc:
                    if "workflow state does not exist" not in str(exc):
                        raise
                else:
                    context = current.get("context") or {}
                    if (
                        context.get("workflowProfile") == "qualification"
                        and context.get("targetContextLocked") is True
                    ):
                        locked_context = context
            target = None
            if args.workflow_profile == "qualification":
                target = resolve_qualification_target(
                    args.solution,
                    tenant_id=args.tenant_id,
                    subscription_id=args.subscription_id,
                    workspace_resource_id=args.workspace_resource_id,
                    workspace_customer_id=args.workspace_customer_id,
                    confirm_configured_target=args.confirm_configured_target,
                    locked_context=locked_context,
                )
            result = initialize_workflow(
                args.solution,
                tenant_id=target["tenantId"] if target else args.tenant_id,
                subscription_id=(
                    target["subscriptionId"] if target else args.subscription_id
                ),
                workspace_resource_id=(
                    target["workspaceResourceId"] if target else args.workspace_resource_id
                ),
                workspace_customer_id=(
                    target["workspaceCustomerId"] if target else args.workspace_customer_id
                ),
                version_bump=args.version_bump,
                workflow_profile=args.workflow_profile,
                yolo=True if args.yolo else None,
                campaign_id=args.campaign_id,
                new_run=args.new_run,
            )
        elif args.command == "workflow-budget":
            result = budget_summary(args.solution, args.campaign_id)
        elif args.command == "workflow-budget-extend":
            result = extend_budget(
                args.solution,
                args.campaign_id,
                dimension=args.dimension,
                new_limit=args.new_limit,
                actor=args.actor,
                reason=args.reason,
                evidence_reference=args.reference,
            )
        elif args.command == "workflow-budget-reconcile":
            result = reconcile_pending_operation(
                args.solution,
                args.campaign_id,
                args.operation_id,
                status=args.status,
                elapsed_seconds=args.elapsed_seconds,
                actor=args.actor,
                reason=args.reason,
                evidence_reference=args.reference,
            )
        elif args.command == "workflow-budget-reconcile-legacy":
            baseline_path = Path(args.baseline).expanduser().resolve()
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            result = reconcile_legacy_usage(
                args.solution,
                args.campaign_id,
                consumed=baseline,
                actor=args.actor,
                reason=args.reason,
                evidence_reference=args.reference,
            )
        elif args.command == "workflow-budget-deadline":
            result = set_observation_deadline(
                args.solution,
                args.campaign_id,
                test_id=args.test_id,
                deadline_at=args.deadline_at,
                approval_reference=args.approval_reference,
                actor=args.actor,
                reason=args.reason,
            )
        elif args.command == "workflow-status":
            result = workflow_status(args.solution)
        elif args.command == "workflow-next":
            result = next_workflow_stage(args.solution)
        elif args.command == "workflow-start-stage":
            result = start_workflow_stage(args.solution, args.stage)
        elif args.command == "workflow-complete-stage":
            result = complete_workflow_stage(
                args.solution,
                args.stage,
                status=args.status,
                message=args.message,
                artifacts=_key_values(args.artifact),
                evidence=args.evidence,
            )
        elif args.command == "workflow-yolo":
            if not args.run_id:
                raise ValueError("workflow-yolo requires an explicit --run-id")
            result = run_yolo_authoring(args.solution)
        elif args.command == "workflow-yolo-refresh":
            if not args.run_id:
                raise ValueError("workflow-yolo-refresh requires an explicit --run-id")
            result = refresh_yolo_authoring(args.solution)
        else:
            result = runtime_validation_plan(args.solution)
    except (OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        if selection is not None:
            reset_run_selection(selection)

    _print(result)
    if args.command == "validate" and result["invalid"]:
        return 1
    if args.command == "validate-advanced-hunting" and (
        result["invalid"] or result["blocked"]
    ):
        return 1
    if args.command == "validate-sentinel-sdk" and (
        result["invalid"] or result["blocked"] or not result.get("familyComplete", False)
    ):
        return 1
    if args.command == "record-runtime-validation" and (
        result["invalid"] or result["blocked"]
    ):
        return 1
    if args.command in ("deploy", "deploy-analytic-rules") and result["failed"]:
        return 1
    if args.command == "complete-alert-parity" and result["status"] != "passed":
        return 1
    if args.command == "abort-alert-parity" and result["status"] != "aborted":
        return 1
    if (
        args.command == "verify-delegated-app-readback"
        and result.get("status") != "readback-verified-private-config-completed"
    ):
        return 1
    if (
        args.command == "diagnose-app-readback-scopes"
        and result.get("status") != "required-scopes-present"
    ):
        return 1
    if args.command == "convert" and (result["needsReview"] or result["conflicts"]):
        return 1
    if (
        args.command == "workflow-complete-stage"
        and result["status"] != "passed"
    ):
        return 1
    if args.command == "workflow-yolo" and (
        result["status"] != "active"
        or result.get("validationStatus") == "blocked"
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
