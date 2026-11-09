# Tracked follow-up areas

These are curated future-work areas, not commitments, completed capabilities,
or a release guarantee. Scope, priority, ownership, and approval remain subject
to separate review.

This list records candidate known-limitations and follow-up work for the V1
PREVIEW toolkit.

## Publication security gate

Resolve security findings and independently re-review the corrected changes
before publishing. This is a publication gate, not optional roadmap work.
External ARM-TTK/Azure validation-service limitations, when encountered,
should be reported separately from toolkit code defects and do not by
themselves establish a toolkit fix is required.

## Recently completed in V1 PREVIEW

- **Make workbook `dependsOn` reference canonical parser IDs during packaging.**
  Bound reviewed workbook function prerequisites to actual
  `Microsoft.OperationalInsights/workspaces/savedSearches` resources in the
  same enclosing ARM template using canonical `[variables('parserObject<N>')._parserId<N>]`
  references (with literal `resourceId(...)` fallback), enforced unconditional
  parser installation, and verified exact resource mapping in packaging regressions.
- **Default hourly Sentinel rules to the native XDR lookback.** For supported
  rules with a one-hour Sentinel frequency and lookback, retained the hourly
  Custom Detection frequency (`PT1H`) and accepted the native four-hour
  ingestion-based lookback (`PT4H`) by default without pausing for timing-only
  approval, recording `eventTimeWindow` provenance and exact source/target
  hashes while keeping `parityClaimed: false`.
- **Map eligible Sentinel `kind: NRT` rules to Continuous (`PT0S`) Custom Detections.**
  Mapped eligible single-table `kind: NRT` rules to `kind: CustomDetection`
  with `schedule.frequency: "PT0S"` (`Edm.Duration` zero duration, while
  normalizing legacy `"NRT"` strings at Graph/ARM boundaries), surfacing
  incompatible multi-table, join, union, or aggregate NRT queries for explicit
  review.
- **Accept standard `_`-prefixed built-in ASIM parsers (`_ASim_*` and `_Im_*`).**
  Recognized built-in unifying ASIM parsers starting with `_` as supported in
  both Custom Detections and Defender Workbooks.
- **Inherit the solution release version for updated content & preserve lexical
  YAML version text.** Assigned generated/updated detections the solution
  release version in `[3.1.0, 4.0.0)` while preserving exact lexical
  `contentProvenance.source.version` strings and validating content hash
  identities.
- **Collect review feedback in one consolidated batch & guide users to the next
  migration blocker review.** Added `review-packet` / `consolidated-review-plan`
  CLI helpers and `nextStepRecommendation` / `nextBlockerReview` status and
  report summaries.
- **Set release-note dates predictably.** Defaulted release-note dates to
  today's date in `DD-MM-YYYY` format unless overridden.
- **Validate XDR Detections and Defender Workbooks in `.script/local-validation/`.**
  Added `validate-xdr-content.py` and `xdr-detection` / `xdr-workbook`
  validators to `build-and-validate.ps1` with explicit `SKIP` visibility.
- **Verify ARM templates through lab deployment by default (`lab-deployment`) with
  preflight preapproval.** Defaulted ARM validation to `lab-deployment` for
  Authoring and Qualification (with explicit `arm-ttk` selection supported in
  Authoring), added preflight preapproval prompts stating `X Sentinel rules,
  Y workbooks, and Z custom detections`, recorded target/SHA-256 deployment
  validation findings (`functionalQualificationVerified: false`,
  `alertParityVerified: false`), and surfaced `SKIP (lab-deployment selected as
  ARM validation route)` in `build-and-validate.ps1`.
- **Reconcile Qualification readiness and private configuration/support exports.**
  Added `assess_qualification_readiness` (separating `authorizationChecks`,
  `deploymentPermissionReadiness`, and `ingestionPermissionReadiness`) and
  `audit_private_config_and_support_export` to verify secret/private-target
  hygiene before export.
- **Add operator visibility, scheduled migration status reminders, single-owner
  execution leases, and safe approval forwarding.** Added
  `workflow-status-reminder` (with `suppressedNoChange`, workflow diagram, and
  batch duration explanation), `workflow-execution-owner`
  (`duplicate_executor_blocked` lease protection), and
  `workflow-forward-approval` (hash-bound `(runId, operation, approvedBy,
  forwardedToOwnerId, exactScope, approvalSha256)` forwarding).
- **Enforce clean workbook publication (`public-workbook-v1`) and Marketplace
  customer usage attribution discovery (`trackingId`).** Added
  `workbook-publication-plan` and `workbook-publication-clean` so published
  `XDR Workbooks/*.json` strip authoring review metadata while preserving
  dependency provenance, added anonymous Marketplace catalog discovery and
  persistence of `SolutionMetadata.json` `trackingId` in V3.1 packaging, and
  preserved `Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV3.ps1`
  unchanged from `upstream/master` (with optional legacy V3 compatibility
  routing in `.script/package-automation/package-generator.ps1`).
- **Default all workflow entry points and agent adapters to `authoring`.**
  Aligned CLI (`workflow-init`), canonical workflow instructions, and agent
  adapters (`AGENTS.md`, `CLAUDE.md`, `.github`, `.claude`, `.cursor`, and
  `.windsurf`) to default to the `authoring` profile and route packaging through
  `package-v3-1` (V3.1).
- **Organize Python implementation into `solution_manager` capability subfolders.**
  Moved the 53 implementation modules into `solution_manager/` grouped by
  capability (`core/`, `authoring/`, `migration/`, `qualification/`,
  `packaging/`, `reporting/`, and `research/` scaffold) with `cli.py` at the
  package root and backwards-compatible `sentinel_xdr_migration` module aliases.
- **Preserve non-Log-Analytics query types and Azure resource-protection pickers
  in Defender workbooks by default.** Preserved Azure Resource Graph (`queryType: 1`,
  `microsoft.resourcegraph/resources`) tiles and kept `{subscription}` /
  resource-protection pickers active when referenced by preserved non-Log-Analytics
  queries (`preservedByResourceProtectionQueries`).
- **Extend conversion logic to migrate `SecurityAlert` and `SecurityIncident`
  queries to `AlertInfo` and `AlertEvidence` (`AlertEntities`) tables.** Added
  deterministic table and column conversion rules (`SystemAlertId -> AlertId`,
  `AlertName/DisplayName -> Title`, `AlertSeverity -> Severity`,
  `ProviderName -> DetectionSource`, `ProductName -> ServiceSource`,
  `Tactics -> AttackTechniques`/`Category`, `TimeGenerated -> Timestamp`) with
  `AlertEvidence` left-outer join synthesis across rules and workbooks.
- **Support automatic row-level query rewrite for `kind: NRT` rules with cosmetic
  `summarize` wrappers.** Added deterministic `rewrite_cosmetic_nrt_summarize`
  to convert trailing timestamp/count `summarize` wrappers into row-level
  projections while preserving `schedule.frequency: "PT0S"`, and automatically
  fell back behavioral `summarize` NRT rules to `PT1H` / `PT4H`.
- **Add catalog-specific validation routing for `Sample Data/Tables/` in
  `.script/sampleDataValidator.ts`.** Routed `Sample Data/Tables/<TableName>/base-event.json`
  and `metadata.json` through `IsValidTableCatalogSampleData` and RFC 2606 /
  contoso / example email sanitation checks.
- **Safely capture user decisions into the submitted work for all flows under
  Solution Manager.** Added `solution_manager.reporting.decision_manifest`
  (`decision-manifest-v1`) with fail-closed privacy verification and
  `decisionManifestSummary` projection into solution reports.
- **Deliver review-gate notifications reliably.** Added
  `solution_manager.core.review_notifications` to persist `pending`,
  `delivered`, `acknowledged`, and `delivery_failed` notification states bound
  to `(runId, reviewPacketSha256)` with restart reconciliation and deduplication.
- **Implement 5-stage end-to-end `QualificationOrchestrator` and promotion gate.**
  Added `solution_manager.qualification.orchestrator` (`preflight`,
  `deployment`, `mock_ingestion`, `rule_parity`, `workbook_qualification`) and
  `evaluate_qualification_promotion_gate` to verify end-to-end qualification
  readiness before promoting `qualification` as the default profile.
- **Raise minimum V3.1 solution release version floor to `>= 3.2.2 and < 4.0.0`.**
  Updated V3.1 solution version policy documentation and workflow examples to
  require canonical solution versions in `[3.2.2, 4.0.0)`.
- **Add cross-surface `AlertEvidence` Azure resource column compatibility aliases
  and document deterministic `SecurityAlert`/`SecurityIncident` mappings.**
  Added `ALERT_EVIDENCE_CROSS_SURFACE_EXPRESSIONS` using
  `coalesce(tostring(column_ifexists(...)))` so migrated `SecurityAlert` and
  `SecurityIncident` queries referencing `ResourceID`/`AzureResourceId`,
  `ResourceType`/`AzureResourceType`, or `SubscriptionId`/`AzureSubscriptionId`
  execute identically across Defender XDR Advanced Hunting and Azure Monitor /
  Sentinel Log Analytics.
- **Bundle Microsoft Graph Bicep/ARM template (`grant-graph-hunting-scopes.arm.json`)
  and `build_missing_graph_scope_arm_offer` remediation helper.** Added bundled
  `grant-graph-hunting-scopes.bicep` and `grant-graph-hunting-scopes.arm.json`
  templates under `solution_manager/qualification/templates/` and
  `build_missing_graph_scope_arm_offer` to offer explicit-approval deployment of
  `Microsoft.Graph/applications@v1.0`, `servicePrincipals@v1.0`, and
  `oauth2PermissionGrants@v1.0` when `ThreatHunting.Read.All` or
  `CustomDetection.ReadWrite.All` is missing.
- **Align GitHub Actions ARM-TTK CI with local V3.1 filters and `lab-deployment`
  qualification mode.** Synchronized `.github/actions/entrypoint.ps1` with
  `.script/local-validation/run-arm-ttk.ps1` (`-Skip @("Template Should Not
  Contain Blanks", "URIs Should Be Properly Constructed")`, exempt `"packageId"`,
  `"fromTemplateId"`, `"columnId"`, and `customDetails` `*Id` keys in
  `IDs Should Be Derived From ResourceIDs`, and fixed nested-template
  `Summary.Fail` decrement math), guarded `Expand-AzTemplate.ps1` against
  `"microsoft.resources/deployments/write"` string literals inside KQL
  `queryText`, and allowed `.github/workflows/arm-ttk-validations.yaml` to
  recognize verified `lab-deployment` qualification evidence for V3.1
  `languageVersion: "2.0"` `MicrosoftSecurity` resources (`#15397`).
- **Rewrite scalar `dynamic([...])` and `mv-apply` filters in `kind: NRT` (`PT0S`)
  Custom Detections for the Defender XDR streaming compiler.** Added
  `rewrite_nrt_streaming_constructs` in `converter.py` to inline `let <var> =
  dynamic([...]);` lists and rewrite scalar `mv-apply` filter stages into
  streaming-compatible predicates, and added `_assess_nrt_eligibility` checks
  rejecting residual `dynamic([...])` and `mv-apply` / `mv-expand` in `PT0S`
  rules (`HuntingRuleQueryStreamingNotSupported`).

- **Flip default workflow profile from `authoring` to `qualification`.**
  Switched the default `--workflow-profile` in `solution_manager/cli.py`,
  `initialize_workflow` in `solution_manager/core/workflow.py`,
  `Tools/SentinelToXDRMigration/agent-workflows/end-to-end-migration.md`, and
  agent adapters (`AGENTS.md`, `CLAUDE.md`, `.github`, `.claude`, `.cursor`, and
  `.windsurf`) from `authoring` to `qualification`, preserving
  `--workflow-profile authoring` as an explicit offline/ISV fallback when no
  live lab is available.
- **Enable XDR Custom Detections and Sentinel Analytic Rules during
  Qualification flow.** Enabled deployed Defender XDR Custom Detections and
  Sentinel Analytic Rules during lab Qualification, exercising live rule
  enablement and the Defender XDR NRT streaming compiler before disabling or
  cleaning up rules after the test window.
- **Reject false-success packaging results in V3.1 without changing legacy V3
  flow.** Enforced strict artifact, resource, and error checks in V3.1 packaging
  acceptance while preserving zero as the normal success exit code.
- **Extend KQL static validations to XDR artifacts and allow Qualification mode
  overrides.** Extended `.script/tests/KqlvalidationsTests` and local validation
  to `XDR Detections/*.yaml` and `XDR Workbooks/*.json`, and allowed verified
  live `qualification` evidence to override offline static KQL analyzer false
  positives.
- **Instrument NPF metrics in CI labeler, validation, and qualification
  artifacts.** Added `passesPerSolution`, `commitPasses`, `highestStage`,
  `verdicts`, `runNumber`, `stageTimestamps`, `verdict`, `verdictReasons`,
  `overrides[]`, and `operatorHash` across `.github/workflows/npf-pr-labeler.yaml`
  and `solution_manager`.
- **Unblock six identity/risk tables, preserve `TimeGenerated` everywhere, and
  allow lab/connector table evidence to override static catalogs.** Changed
  `AADProvisioningLogs`, `AADRiskyUsers`, `AADUserRiskEvents`, `ADFSSignInLogs`,
  `RiskyUsers`, and `UserRiskEvents` to `tier: "1to1"`, removed
  `TimeGenerated -> Timestamp` rewrites across detections and workbooks, and
  threaded reviewed/lab/connector table evidence (`allowed_tables` /
  `known_tables`) through dependency planning, workbook conversion, and
  validators.
- **Surface CI `DocumentsLinkValidation` locale failures in validation mode and
  normalize URL verification evidence.** Extended `VAL-URL-01` and `validate`
  mode (`validate_solution` and `validate_content`) to scan all solution text
  files with the CI locale regex and recommend locale-stripped URLs, and
  normalized `url` / `resolvedUrl` fields in URL verification evidence
  (`QUAL-URL-01`).

## Candidate follow-ups

- [ ] `[P0]` **Support multi-tactic mappings in XDR Custom Detections (`XDR Detections/*.yaml` and V3.1 packaging):** Preserve all Sentinel `tactics[]` across `converter.py` (`solution_manager/migration/converter.py`), `customDetections.ps1` (`Tools/Create-Azure-Sentinel-Solution/common/customDetections.ps1`), and `deploy.py` instead of truncating `tactics` to `tactics[0]` in `detectionAction.alertTemplate.category`, aligning with Microsoft Graph `/beta/security/rules/detectionRules` and Defender XDR multi-tactic support (e.g., comma-separated `category` or multi-tactic schema fields).
- [ ] `[P0]` **Ensure `qualification` is the enforced default across all remaining entry points and flows:** Audit and update any remaining CLI subcommands, orchestrator entry points, validation/reporting helpers, and documentation/memory references that still fall back to `authoring` or offline-only stubs so `qualification` is consistently enforced end-to-end by default.
- [ ] `[P0]` **Support secondary workspaces for XDR Custom Detections:** Support targeting, deploying, and qualifying XDR Custom Detections (`XDR Detections/*.yaml`, Advanced Hunting queries, and schema discovery via `workspaceId`) against secondary Log Analytics workspaces onboarded to Defender XDR in addition to the primary workspace.
- [ ] `[P0]` **Enforce mandatory AI-ready table schema requirements (table & column descriptions) in both Validation and Qualification modes and adopt the new Graph Advanced Hunting schema endpoints:** Require every solution table (`Microsoft.OperationalInsights/workspaces/tables` in `Data Connectors/*_tables.json` and `Package/mainTemplate.json`) to provide a non-empty, meaningful table description (`properties.schema.description`) and 100% column description coverage (`properties.schema.columns[].description`) as mandatory blocking checks in both Validation mode (`VAL-TBL-01..03` in `validate_solution` / `validate_content` and `pr_check_runner.py`) and Qualification mode (`QUAL-TBL-01..03` live readback, leaving deep schema and entity mapping out of Phase 1). Start using the new Microsoft Graph Security Advanced Hunting schema and query endpoints (`GET /beta/security/getHuntingSchema`, `GET /beta/security/getHuntingSchemaTables` / `getHuntingSchemaTables(workspaceId=<guid>)`, and `GET /beta/security/getRunHuntingQuery(...,workspaceId=<guid>)`) alongside ARM `Tables - Get` to verify live table/column descriptions and workspace-scoped schema exposure in Defender XDR.
- [ ] `[P1]` **Make live Playwright browser execution the enforced default in Qualification mode:** Wire `QualificationOrchestrator` and `verify_workbook_playwright_rendering` (`solution_manager/qualification/workbook_playwright.py`) to execute real Playwright browser verification (`capture_workbook_browser` / `execute_workbook_browser` in `workbook_browser.py` with `producer: "playwright-dom-v1"`) by default instead of falling back to the `playwright_runner=None` pass stub when `enable_playwright=True`, and require real Playwright DOM/screenshot traversal evidence for `E2E-Q05` and `TK-Q06`.
- [ ] `[P1]` **Agent to check that detection tactics match the detection intent and recommend additional TTPs (optional):** Have the agent evaluate whether declared MITRE ATT&CK `tactics` and `relevantTechniques` on Sentinel Analytic Rules and XDR Custom Detections align with the query logic and detection intent, and surface optional recommendations for missing or better-matching TTPs during authoring/review.
- [ ] `[P1]` **Support secondary workspaces for Defender XDR Workbooks:** Support targeting, deploying, and qualifying Defender XDR Workbooks (`XDR Workbooks/*.json` and workbook queries/pickers via `workspaceId`) against secondary Log Analytics workspaces onboarded to Defender XDR in addition to the primary workspace.
- [ ] `[P2]` **Backfill multi-tactic mappings across already-migrated XDR Custom Detections:** Re-convert and repackage existing migrated solutions whose source Sentinel Analytic Rules declare multiple `tactics` so their `XDR Detections/*.yaml` and packaged `mainTemplate.json` preserve the full tactic set instead of a single primary tactic.
- [ ] `[P2]` **Incorporate the ASIM Content PR Validation workflow (QTP & ITP) into the Qualification flow:** Integrate ASIM query-time parser (QTP) and ingestion-time parser (ITP) discovery and qualification as a shared target-based subsystem across `QualificationOrchestrator` and `pr_check_runner.py` (detailed plan in `Tools/ignored/ASIM_Qualification_Integration_Plan.md`):
  - **Static checks (`VAL-ASIM-01..03`):** QTP YAML template/naming/schema/parameter contract (`VerifyASimParserTemplate.py`), sample CSV fixture typing and single-`Type` validation (`Sample Data/ASIM/*_IngestedLogs.csv`), and ITP transform KQL/`ParserFilterQuery`/`SourceRawTable`/`TargetASIMTable` validation (`asim_ingest_time_validation.py`).
  - **Live Sentinel QTP/ITP checks (`QUAL-ASIM-01..06`, `QUAL-ASIM-09`):** Timestamp-rebased fixture preparation (100 ns slot isolation), custom `_CL` table and temporary pass-through/transform DCR setup, `LogsIngestionClient` upload and visibility verification, query-local `ASimSchemaTester` (`QUAL-ASIM-02`), `ASimDataTester` (`QUAL-ASIM-03`), parameterized `ASimFilteringTest` (`QUAL-ASIM-04`), ITP transformation DCR ingestion into `Microsoft-{TargetASIMTable}` (`QUAL-ASIM-05`), optional QTP-vs-ITP parity (`QUAL-ASIM-06`), and deterministic temporary DCR cleanup (`QUAL-ASIM-09`).
  - **Live Defender XDR Advanced Hunting checks (`QUAL-ASIM-07..08`) & Evidence:** Verify `_ASim_*` / `_Im_*` built-in/saved function provenance and workspace-scoped backing tables via `GET /beta/security/getHuntingSchema` and `GET /beta/security/getHuntingSchemaTables(workspaceId=<guid>)` (`QUAL-ASIM-07`), execute workspace-scoped AH invocation via `POST /beta/security/runHuntingQuery` (`QUAL-ASIM-08`), and emit `Evidence/asim-qualification.json` into the HTML qualification report.

Any future environment write remains separately gated by explicit approval
immediately before the exact operation. No cloud action is authorized by this
roadmap.
