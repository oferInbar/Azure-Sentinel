# Tracked follow-up areas

These are curated future-work areas, not commitments, completed capabilities,
or a release guarantee. Scope, priority, ownership, and approval remain subject
to separate review.

This list records candidate known-limitations and follow-up work for the V1
PREVIEW toolkit.

## Publication & validation note

Publishing follows the repository review process. External validation-tool
limitations should be reported separately from toolkit defects.

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
  migration blocker review.** Added consolidated review-packet CLI helpers and
  next-step blocker summaries in status and report outputs.
- **Set release-note dates predictably.** Defaulted release-note dates to
  today's date in `DD-MM-YYYY` format unless overridden.
- **Validate XDR Detections and Defender Workbooks in `.script/local-validation/`.**
  Added `validate-xdr-content.py` and `xdr-detection` / `xdr-workbook`
  validators to `build-and-validate.ps1` with explicit `SKIP` visibility.
- **Verify ARM templates through lab deployment by default (`lab-deployment`) with
  preflight preapproval.** Defaulted ARM validation to `lab-deployment` for
  Authoring and Qualification (with explicit `arm-ttk` selection supported in
  Authoring), added preflight preapproval prompts stating `X Sentinel rules,
  Y workbooks, and Z custom detections`, and surfaced `SKIP (lab-deployment
  selected as ARM validation route)` in `build-and-validate.ps1`.
- **Reconcile Qualification readiness and private configuration/support exports.**
  Added preflight permission readiness checks and support-export hygiene
  verification before export.
- **Support single-owner execution leases and scoped approval forwarding.**
  Added workflow status reminders, single-owner execution leases, and scoped
  approval forwarding for multi-stage solution runs.
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
  Grouped implementation modules under `solution_manager/` by capability
  (`core/`, `authoring/`, `migration/`, `qualification/`, `packaging/`, and
  `reporting/`) with `cli.py` at the package root and backwards-compatible
  `sentinel_xdr_migration` module aliases.
- **Preserve non-Log-Analytics query types and Azure resource-protection pickers
  in Defender workbooks by default.** Preserved Azure Resource Graph (`queryType: 1`,
  `microsoft.resourcegraph/resources`) tiles and kept `{subscription}` /
  resource-protection pickers active when referenced by preserved non-Log-Analytics
  queries.
- **Extend conversion logic to migrate `SecurityAlert` and `SecurityIncident`
  queries to `AlertInfo` and `AlertEvidence` (`AlertEntities`) tables.** Added
  deterministic table and column conversion rules (`SystemAlertId -> AlertId`,
  `AlertName/DisplayName -> Title`, `AlertSeverity -> Severity`,
  `ProviderName -> DetectionSource`, `ProductName -> ServiceSource`,
  `Tactics -> AttackTechniques`/`Category`) with `AlertEvidence` left-outer join
  synthesis across rules and workbooks.
- **Support automatic row-level query rewrite for `kind: NRT` rules with cosmetic
  `summarize` wrappers.** Converted trailing timestamp/count `summarize`
  wrappers into row-level projections while preserving `schedule.frequency: "PT0S"`,
  and automatically fell back behavioral `summarize` NRT rules to `PT1H` / `PT4H`.
- **Add catalog-specific validation routing for `Sample Data/Tables/` in
  `.script/sampleDataValidator.ts`.** Routed `Sample Data/Tables/<TableName>/base-event.json`
  and `metadata.json` through `IsValidTableCatalogSampleData` and RFC 2606 /
  contoso / example email sanitation checks.
- **Safely capture user decisions into the submitted work for all flows under
  Solution Manager.** Added privacy-verified decision manifest summaries to
  solution reports.
- **Deliver review-gate notifications reliably.** Added persistent review-gate
  notification tracking with restart reconciliation and deduplication.
- **Implement 5-stage end-to-end Qualification orchestration.** Added
  end-to-end qualification orchestration across preflight, deployment, mock
  ingestion, rule parity, and workbook qualification.
- **Raise minimum V3.1 solution release version floor to `>= 3.2.2 and < 4.0.0`.**
  Updated V3.1 solution version policy documentation and workflow examples to
  require canonical solution versions in `[3.2.2, 4.0.0)`.
- **Add cross-surface `AlertEvidence` Azure resource column compatibility aliases
  and document deterministic `SecurityAlert`/`SecurityIncident` mappings.**
  Added cross-surface `coalesce(tostring(column_ifexists(...)))` expressions so
  migrated `SecurityAlert` and `SecurityIncident` queries referencing
  `ResourceID`/`AzureResourceId`, `ResourceType`/`AzureResourceType`, or
  `SubscriptionId`/`AzureSubscriptionId` execute identically across Defender XDR
  Advanced Hunting and Azure Monitor / Sentinel Log Analytics.
- **Surface required Microsoft Graph permissions for Advanced Hunting and
  custom-detection validation.** Surfaced required Microsoft Graph permissions
  (`ThreatHunting.Read.All` and `CustomDetection.ReadWrite.All`) during
  preflight checks and required explicit administrator approval before granting
  permissions.
- **Align local and GitHub Actions ARM validation for V3.1 packages.**
  Synchronized local and GitHub Actions ARM validation for V3.1 packages,
  including public-preview Microsoft Security custom-detection resources.
- **Support continuous (`NRT`) Custom Detections with row-level predicates.**
  Supported continuous (`NRT`) Custom Detections with row-level predicates,
  automatically rewriting or scheduling queries hourly when continuous
  compilation is not supported.
- **Flip default workflow profile from `authoring` to `qualification`.**
  Switched the default `--workflow-profile` across CLI entry points, canonical
  workflow instructions, and agent adapters (`AGENTS.md`, `CLAUDE.md`, `.github`,
  `.claude`, `.cursor`, and `.windsurf`) from `authoring` to `qualification`,
  preserving `--workflow-profile authoring` as an explicit offline/ISV fallback
  when no live lab is available.
- **Enable XDR Custom Detections and Sentinel Analytic Rules during
  Qualification flow.** Enabled deployed Defender XDR Custom Detections and
  Sentinel Analytic Rules during lab Qualification, exercising live rule
  enablement before disabling or cleaning up rules after the test window.
- **Reject false-success packaging results in V3.1 without changing legacy V3
  flow.** Enforced strict artifact, resource, and error checks in V3.1 packaging
  acceptance while preserving zero as the normal success exit code.
- **Extend static KQL validations to XDR artifacts.** Extended static KQL
  validations to `XDR Detections/*.yaml` and `XDR Workbooks/*.json`, and allowed
  reviewed live lab verification results to resolve static-analyzer false
  positives.
- **Record anonymous pass/fail stage summaries for solution pull requests.**
  Added stage-level pass/fail summaries for solution pull request validation and
  qualification runs.
- **Unblock six identity/risk tables, preserve `TimeGenerated` everywhere, and
  allow lab/connector table evidence to override static catalogs.** Marked
  `AADProvisioningLogs`, `AADRiskyUsers`, `AADUserRiskEvents`, `ADFSSignInLogs`,
  `RiskyUsers`, and `UserRiskEvents` as directly usable in Advanced Hunting,
  removed `TimeGenerated -> Timestamp` rewrites across detections and workbooks,
  and allowed reviewed lab or data-connector table evidence to supplement static
  table catalogs.
- **Surface CI `DocumentsLinkValidation` locale failures in validation mode and
  normalize URL verification evidence.** Extended validation mode to scan all
  solution text files with the CI locale URL rule and recommend locale-stripped
  URLs, and normalized `url` / `resolvedUrl` fields in URL verification
  evidence.

## Candidate follow-ups

- [ ] `[P0]` **Support multi-tactic mappings in XDR Custom Detections (`XDR Detections/*.yaml` and V3.1 packaging):** Preserve all Sentinel `tactics[]` across conversion, V3.1 ARM packaging, and deployment instead of truncating `tactics` to a single entry, aligning with the public Microsoft Graph `detectionRule` and custom-detection Bicep multi-tactic schema fields.
- [ ] `[P0]` **Ensure `qualification` is the enforced default across all remaining entry points and flows:** Audit and update any remaining CLI subcommands, orchestrator entry points, validation/reporting helpers, and documentation references that still fall back to `authoring` or offline-only stubs so `qualification` is consistently enforced end-to-end by default.
- [ ] `[P0]` **Support secondary workspaces for XDR Custom Detections:** Support targeting, deploying, and qualifying XDR Custom Detections (`XDR Detections/*.yaml`, Advanced Hunting queries, and schema discovery via `workspaceId`) against secondary Log Analytics workspaces onboarded to Defender XDR in addition to the primary workspace.
- [ ] `[P0]` **Enforce mandatory table and column schema descriptions in both Validation and Qualification modes and adopt the Microsoft Graph Advanced Hunting schema APIs:** Require every solution table (`Microsoft.OperationalInsights/workspaces/tables` in `Data Connectors/*_tables.json` and `Package/mainTemplate.json`) to provide a non-empty, meaningful table description (`properties.schema.description`) and 100% column description coverage (`properties.schema.columns[].description`) as mandatory blocking checks in both Validation mode and Qualification mode. Use the Microsoft Graph Security Advanced Hunting schema and query APIs alongside ARM `Tables - Get` to verify live table/column descriptions and workspace-scoped schema exposure in Defender XDR.
- [ ] `[P1]` **Make live Playwright browser verification the enforced default in Qualification mode:** Require real browser rendering verification (DOM traversal and screenshots) during workbook qualification by default instead of optional offline stubs.
- [ ] `[P1]` **Agent to check that detection tactics match the detection intent and recommend additional TTPs (optional):** Have the agent evaluate whether declared MITRE ATT&CK `tactics` and `relevantTechniques` on Sentinel Analytic Rules and XDR Custom Detections align with the query logic and detection intent, and surface optional recommendations for missing or better-matching TTPs during authoring/review.
- [ ] `[P1]` **Support secondary workspaces for Defender XDR Workbooks:** Support targeting, deploying, and qualifying Defender XDR Workbooks (`XDR Workbooks/*.json` and workbook queries/pickers via `workspaceId`) against secondary Log Analytics workspaces onboarded to Defender XDR in addition to the primary workspace.
- [ ] `[P2]` **Backfill multi-tactic mappings across already-migrated XDR Custom Detections:** Re-convert and repackage existing migrated solutions whose source Sentinel Analytic Rules declare multiple `tactics` so their `XDR Detections/*.yaml` and packaged `mainTemplate.json` preserve the full tactic set instead of a single primary tactic.
- [ ] `[P2]` **Incorporate the ASIM Content PR Validation workflow (QTP & ITP) into the Qualification flow:** Integrate ASIM query-time parser (QTP) and ingestion-time parser (ITP) discovery and qualification into the Qualification flow using the public ASIM validation scripts (`VerifyASimParserTemplate.py`, `ASimSchemaTester`, `ASimDataTester`, `ASimFilteringTest`, and `asim_ingest_time_validation.py`), sample CSV fixtures (`Sample Data/ASIM/*_IngestedLogs.csv`), temporary lab test resources, and Microsoft Graph Security Advanced Hunting schema and workspace-scoped query APIs.

## Community Feature Requests & Feedback

Solution authors, ISV partners, and community contributors can propose new
capabilities or workflow improvements for the Sentinel-to-Defender-XDR Solution
Manager toolkit in two ways:

1. **Open a GitHub Issue (recommended):** Use the
   [Solution Manager & XDR Migration Feature Request template](https://github.com/Azure/Azure-Sentinel/issues/new?template=solution_manager_feature_request.yml&labels=Solution-Manager,enhancement&title=%5BSolution+Manager%5D+Feature+Request%3A+)
   to describe the workflow stage, artifact type, problem statement, and
   proposed behavior.
2. **Submit a lightweight Pull Request:** Add a row to the
   [Community Proposed Enhancements](#community-proposed-enhancements) table
   below linking to your issue or PR. Maintainers triage community proposals
   and promote accepted items into `## Candidate follow-ups` with a priority
   tag (`[P0]`, `[P1]`, or `[P2]`).

## Community Proposed Enhancements

| Proposal | Workflow Stage / Artifact | Use Case & Benefit | Issue / PR | Status |
| :--- | :--- | :--- | :--- | :--- |
| _Example: Custom parser parameter validation hints_ | _Validation / ASIM & Parsers_ | _Surface actionable parameter signature fixes during static validation before live lab deployment_ | _#00000_ | _Template (replace or append rows via PR)_ |

Any future environment write remains separately gated by explicit approval
immediately before the exact operation. No cloud action is authorized by this
roadmap.
