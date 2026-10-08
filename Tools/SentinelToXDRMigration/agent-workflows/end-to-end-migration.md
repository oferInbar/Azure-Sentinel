# Sentinel to Defender XDR migration workflow

This is the canonical, agent-neutral workflow for authoring and migrating
Microsoft Sentinel solution content to Defender XDR Custom Detections. Agent
adapters must reference this document rather than redefine the process.

Deterministic behavior belongs to:

- `Tools\SentinelToXDRMigration`;
- `Tools\Create-Azure-Sentinel-Solution`; and
- the repository validation tools.

Agents coordinate these tools but must not reproduce conversion, validation,
packaging, deployment, or comparison logic in prompts.

## Immutable toolkit boundary

Migration execution must never modify the agent, its skills, backend tools,
schemas, tests, dependency metadata, workflow definitions, safety gates, or
capabilities. Treat these paths as read-only throughout Authoring,
Qualification, retries, and failure recovery:

```text
.github/agents/**
.github/skills/**
Tools/SentinelToXDRMigration/**
Tools/SolutionMigration/**
Tools/Create-Azure-Sentinel-Solution/**
```

If a protected component fails, record the failure and stop the affected
stage. Do not patch, replace, bypass, or reconfigure implementation code as a
runtime workaround. This agent can never perform such changes, regardless of
the requesting user's identity, repository role, ownership, or approval.
Implementation work must be performed manually or by a different development
agent outside the XDR Solution Manager.

## Runtime prerequisite

Run the toolkit only with Python 3.11 or 3.12. If the active interpreter is
outside that range, switch or install the interpreter before continuing.
Environment incompatibility is not permission to edit toolkit source during a
migration workflow.

## Profiles

### Authoring

`Discovery -> Conversion -> Validation -> Packaging -> Report`

This is the ISV publishing workflow. It does not require a tenant, workspace,
deployment, mock ingestion, or alert-parity test.

### Qualification — explicit opt-in

`Discovery -> Conversion -> Validation -> Packaging -> Deployment -> Mock ingestion -> Alert parity -> Report`

This is optional internal or ISV lab testing. Before initialization, require
the user to explicitly choose **Authoring**, **Qualification**, or **Cancel**.
There is no default and no workflow state may be created while the choice is
missing or declined. A configured tenant or workspace does not imply consent.

Qualification requires an approved non-production tenant and workspace plus
separate approval immediately before deployment or ingestion writes.

## Initialize or resume

Install the CLI when necessary:

```powershell
python -m pip install -e Tools\SentinelToXDRMigration
```

Run `workflow-status` first. If state does not exist, or
`context.profileSelectionConfirmed` is not `true`, obtain the explicit profile
selection before initializing:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "<solution-path>" `
  --workflow-profile authoring `
  --version-bump none
```

For an approved qualification run, use `qualification` and include
the complete locked target:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "<solution-path>" `
  --workflow-profile qualification `
  --tenant-id "<tenant-guid>" `
  --subscription-id "<subscription-guid>" `
  --workspace-resource-id "<workspace-arm-id>" `
  --workspace-customer-id "<workspace-customer-guid>" `
  --version-bump "<none-patch-minor-or-major>"
```

Before requesting a workspace value, inspect `doctor`. If
`configuredWorkspaceResourceId` exists, present it for explicit reuse
confirmation. Do not ask the user to retype it. When a new workspace is
approved and resolved, persist it for future solution workflows:

```powershell
sentinel-xdr-migration configure-workspace `
  --tenant-id "<tenant-guid>" `
  --subscription-id "<subscription-guid>" `
  --workspace-resource-id "<workspace-arm-id>" `
  --workspace-customer-id "<workspace-customer-id>"
```

Always resume from persisted state:

```powershell
sentinel-xdr-migration workflow-status --solution "<solution-path>"
sentinel-xdr-migration workflow-next --solution "<solution-path>"
```

Every workflow run stores its reports, configuration, operational state, and logs
under `Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/`. New workflows
get collision-safe timestamp/UUID IDs; resuming keeps the same ID. Use
`workflow-runs --solution "<solution-path>"` to list runs and pass
`--run-id "<id>"` to all solution commands when more than one exists.
Never select the newest run heuristically. `workflow-init --new-run` explicitly
creates an isolated workflow rather than resuming; obtain the normal profile
selection first. Content YAML and package files remain shared solution content,
not per-run snapshots.

When workflow context contains a full `workspaceResourceId`, it is authoritative
for the rest of that run. Pass it explicitly to every Azure command and never
list, rediscover, rank, or scan other workspaces. A Log Analytics customer-ID
GUID may be resolved to an ARM resource ID once, then the ARM ID must be
persisted. A tenant mismatch is an authentication blocker for the selected
workspace, not a reason to choose another workspace.

All live stages must load
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\qualification-target.json` and
verify the tenant, subscription, workspace ARM ID, and workspace customer ID
before proceeding. Specialist tools must not independently discover or infer
any of them.

If the exact ARM path fails, the orchestrator may run
`qualification-diagnose`. It may make one exact customer-ID query restricted
to the locked subscription. When a unique same-identity correction is found,
show the old and proposed resource IDs and require explicit approval before
running `qualification-repair-target --approve-target-update`. No repair may
change tenant, subscription, or customer ID.

The ignored local file
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\workflow-state.json` records stage status, attempts,
timestamps, artifacts, evidence, profile, workspace, and version action. Never
store credentials or tokens in it and never mark a stage passed without
evidence.

Prior flat solution Logs and legacy `Reports/<solution>/sentinel-xdr-migration` (including the old
`AZURE_SENTINEL_REPORTS_ROOT` override) and report files in `XDR Detections`
are read-only fallback locations. Status reads never move or initialize state.
Before resuming writes, run `migrate-reports --solution "<solution-path>"`,
review the file list, and obtain approval for
`migrate-reports --solution "<solution-path>" --run-id "<preview-run-id>" --apply`.
This copies artifacts into that run, preserves originals, and records their hashes.
Honor any prior flat migration receipt before treating newer flat state as
authoritative over archived root Reports. Never import one run's archived
evidence into a new workflow. Conflicting copies,
changed legacy originals after migration, and missing migrated files block
resumption; reconcile explicitly rather than selecting stale evidence.
Never delete legacy state or initialize a replacement to bypass this gate.

All solution Logs are Git-ignored and excluded from content/package inputs.
They may contain raw provider responses and lab identifiers, and must not be
force-added to a PR. An optional, explicit local-only PR evidence export is available:

```powershell
sentinel-xdr-migration export-evidence --solution "<solution-path>" --run-id "<run-id>"
```

Run it only after the selected run is stable. It writes trackable
`Evidence/<run-id>/{summary.md,evidence.json}`, never overwrites an existing
snapshot and does not change operational state, rerun tests or perform cloud
writes. No environment-write approval is needed for this explicit local export.
The header identifies the checked public solution name, profile, recorded status,
current observed solution version, requested version action and actual export
time/tool version. Missing target versions and original export times remain
unknown. An explicitly authorized header-only edit of an older snapshot must
preserve its results/hashes and distinguish new header observations from
historical export facts; `export-evidence` still refuses overwrites.
All recorded statuses, including failures, blocks and not-run results, are
preserved through a fixed allowlist; raw provider data/free-text messages and
tenant identifiers are omitted. Missing and unsupported evidence is explicit.
Hashes anchor current local bytes, not trusted attestation or historical test
binding. Review the snapshot before committing; see the toolkit README for
allowlists and filename-sanitization limits. Evidence is never loaded as resume
state or included in solution content inputs or Marketplace ZIPs.
Persisted filesystem references are solution-relative where possible; resolve
them against the selected solution, not the current shell directory.

Start and complete each stage:

```powershell
sentinel-xdr-migration workflow-start-stage `
  --solution "<solution-path>" `
  --stage discovery

sentinel-xdr-migration workflow-complete-stage `
  --solution "<solution-path>" `
  --stage discovery `
  --status passed `
  --message "Reviewed source inventory" `
  --artifact inspection="Logs\sentinel-xdr-migration\<run-id>\inspection.json" `
  --evidence "Analytic Rules\Example.yaml"
```

Allowed terminal statuses are `passed`, `failed`, and `blocked`. Explain
failed and blocked results. Correct and retry only that stage.

## Stage gates

### Discovery

Run `sentinel-xdr-migration inspect`. Account for every source rule, ID, table,
query, and existing XDR artifact. Reject duplicate IDs, ambiguous provenance,
and content without defensible attacker behavior or observable telemetry.

For content-creator Authoring, assume source-referenced Sentinel tables are
expected to be available in XDR; do not ask whether the target resolves both
tables or directory fields. This is not a deployment-environment guarantee.
The tool owns standard schema resolution: use actually advertised official
schema MCP/API capabilities when authorized, or authoritative Microsoft
documentation, with source/target query-surface and table/alias context.
Do not ask customers to choose `Timestamp`/`TimeGenerated` or field casing.
For custom `_CL` tables, infer only from actual available connector, DCR, or
table definitions; distinguish inferred, schema-verified, and runtime-validated
evidence. Missing/conflicting metadata is a tool/evidence limitation, never
permission to fabricate a schema from the suffix.

This is approved authoring policy; the current finite rename catalog is not a
general schema resolver. See the README's
[current-versus-pending capability matrix](../README.md#content-creator-authoring-policy-and-pending-implementation).

### Conversion

Run `sentinel-xdr-migration convert`. The converter must preserve source Analytic
Rules; source-authoring metadata repairs are a separate step described below. Generated
files belong under `XDR Detections`, remain disabled, and contain source
provenance. Pass only with no conflicts and no unresolved `needsReview` item.
Only deployable detection YAML belongs under `XDR Detections`; conversion
manifests, reports, configuration, validation evidence, and state belong under
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>`.

For an explicitly selected pilot, `convert --rule-id "<source-template-guid>"`
limits writes to one rule while retaining global identity/provenance checks.
Pass the locked `--run-id` and reviewed `--config`; use `--overwrite` only for
the reviewed selected draft. Unknown, malformed, duplicated or excluded selected
IDs fail before writes. Unselected drafts, including config exclusions, are
never changed or deleted. The run's manifest/report are replaced with explicit
rule scope, not merged into full-solution coverage. Earlier passed conversion
and downstream stages are blocked with historical evidence retained.
Do not pass solution conversion/validation stages or package from scoped results:
the workflow and toolkit packager reject them. Full-solution conversion and the
normal gates are required before proceeding. Structural validation of existing
files alone is not conversion coverage. No scoped runtime/deployment or waiver
is introduced; run-local evidence cannot authorize reuse of stale evidence from
other runs sharing the same content. See the README's
[single-rule CLI contract](../README.md#single-rule-conversion).

Explain entity mapping differences using the restricted target mapping contract:
identify retained identifiers, actual lost information, and query-proven
equivalence separately. An unsupported FullName property is not automatically
identity loss. Existing source SID joins are not migration regressions unless
conversion changes their semantics. The README includes a
[concrete Local Admin Group Changes review](../README.md#worked-review-local-admin-group-changes).
Source `requiredDataConnectors` is preserved in optional top-level XDR authoring
metadata, outside deployment `properties`, with exact presence/empty-list and
extensible-entry fidelity. On initial discovery, malformed metadata is a
conversion/structural failure, not a silently dropped declaration or a final
authoring outcome. Older artifacts require an
explicit conversion refresh; no automatic rewrite or gate waiver is implied.
See [dependency preservation](../README.md#connector-dependency-preservation-and-deployment-boundary).
Target registration/dependency translation remains pending design; do not add
an undocumented field to Graph or inner detection-rule properties.

When an entity identifier cannot be preserved equivalently in the final
entity mappings, retain its available query output value **in addition** as
an `alertTemplate.customDetails` column binding. This applies to explicit
mapping overrides as well as automatic conversion. When static output binding
is proven, report this specific mismatch as nonblocking information. Missing or
unproven bindings, conflicts, limits, and dropped values remain warnings or
errors. Supplemental evidence does not restore entity identity or correlation.
Preserve source/override custom details, reject conflicting
explicit keys, and use stable collision-safe keys for added details. Record the
source identifier, bound output column and availability status in conversion
provenance. Do not rewrite KQL or emit known projected-out supplemental columns.
Unknown output bindings require runtime schema verification, not an availability
claim. Respect the documented 20-pair limit without truncation and disclose the
4 KB runtime-value limit. See
[supplemental entity evidence](../README.md#supplemental-entity-evidence-in-custom-details).

For a source lookback shorter than a documented native XDR service window,
conversion may constrain event time only after conservative proof of a single
matching native input and its time-column binding. The filter belongs directly
after the table input, before any aggregation; preserve existing predicates.
Record original/effective/service windows, rationale, and late-ingestion risk.
Joins, unions, historical branches, reassigned columns, or ambiguous semantics
remain `needsReview` without speculative query edits. Explain that the event-time
window is constrained to the original Sentinel lookback while the fixed service
windows remain different. This is not cadence or alert-parity proof; generated
transforms still require ordinary runtime validation. Any applied Advanced
Hunting KQL rewrite invalidates earlier query-runtime evidence and blocks
previously passed validation and downstream stages while retaining old reports
as historical. Rerun the complete Sentinel and Advanced Hunting query families
against the exact current queries. Runtime imports must include the SHA-256 of
the exact query executed; missing or mismatched hashes are blocked. Review
decisions are source/query-hash scoped and expire after a rewrite. Failed KQL
results cannot be relabeled as provider gaps, and fallback is only for provider
failure with a complete-family rerun. Zero rows indicate execution, not parity.
Static/unit checks do not promote a transform to runtime-validated.

Preserve **all** source tactics in source order in authored YAML; multiple
tactics alone are not a review gate. Assign flat source techniques only to
compatible tactics using the repository MITRE catalog, retaining independently
recorded original lists. Unknown/invalid classifications still block. Legacy
single-tactic overrides correct techniques only for their existing named source
tactic, with an explicit warning that they neither narrow nor reorder the
source list. Invalid or incompatible overrides fail rather than lose metadata.
Historical single-tactic draft findings require explicit regeneration, not a
mandatory choice of one tactic for authoring. See the
[MITRE contract](../README.md#mitre-authoring-and-deployment-contracts).

#### Metadata repair and user notification

Within approved content-authoring scope, fix unambiguous schema-defined
metadata inconsistencies at **both ends**: the Sentinel source and its generated
XDR draft. This applies to all metadata, not just connector declarations.
The orchestrator performs a minimal source-authoring maintenance edit and then
uses the existing converter to refresh the affected draft; normal conversion
must never automatically edit source rules. No backend auto-repair engine or
toolkit modification is authorized by this content workflow.

Only mechanical, schema-clear corrections are automatic within that scope.
For example, rename a lone AWSS3 `datatypes` key to required `dataTypes`, keeping
`AWSS3` and `AWSVPCFlow` unchanged. Do not normalize arbitrary extension fields,
valid IDs/data-type values, declaration order, duplicates, or absent/empty lists.
Conflicting keys/values, ambiguous intent, tactics/techniques, entity semantics,
identities and versions require an explicit decision, not an invented fix.
Intentional source/target contract differences are not inconsistencies to erase.

Record file scope, field paths, exact before/after values and schema rationale.
Preserve prior report snapshots and query hashes. For an isolated repair, pass
the selected source `--rule-id`, locked `--run-id`, reviewed `--config` and
approved `--overwrite`; never recreate deliberately deleted unselected drafts.
Verify both metadata structures and their correspondence, unchanged queries,
identities, versions and disabled lifecycle, and untouched unrelated files.
Refresh diagnostics with the existing tools and record repair evidence without
waiving stages or representing scoped output as full-solution coverage.

Inform the user of repairs and outstanding findings separately, including the
affected files and before/after values. Metadata repair clears only the resolved
error; runtime checks remain not run if unexecuted, and unrelated mixed-surface
reviews/warnings remain visible. Identify older comparison pages and exported
evidence as historical unless explicitly refreshed; never attach new hashes to
old snapshot content. See the README's
[metadata repair policy](../README.md#repair-metadata-at-both-ends).

### Validation

If the user declines runtime validation, do not authenticate or run live
queries. Present this disclosure while retaining actual static/schema checks:

> KQL has not been validated because this migration runs without runtime validation. Enable full validation, or review/accept the specific migration checks below.

This is presentation policy, not a new completion mode or waiver. A supported
specific review acceptance is not runtime verification. Report unexecuted
checks as not run; keep failed, blocked, and unresolved-review results visible.
No optional-runtime gate/state implementation is introduced by this policy.
Do not complete an unmet stage, silently bypass it, or treat declined runtime
checks as an environment-only error. The existing validation procedure and
Authoring exception below remain unchanged; if their evidence cannot be
obtained, report the unmet gate and pending implementation rather than success.

Run structural validation. When runtime validation is authorized, validate
original Sentinel and converted Advanced Hunting queries. Prefer capabilities
actually advertised by the official Sentinel Triage MCP; do not invent tool
names. Verify the exact persisted workspace/tenant and read permissions before
live queries. If a provider-level failure interrupts a query family, rerun the
entire family through Log Analytics for Sentinel or Microsoft Graph for
Advanced Hunting and record the provider gap with `record-runtime-validation`
or `validate-advanced-hunting --provider-gap-evidence`. Never mix providers
within one family, and never fall back on a real KQL semantic/runtime error.
Keep structural, runtime, schema-binding, and qualification results separate.
`runtime-validation.graph.json` binds every result to the SHA-256 of the exact
Advanced Hunting query. Imported Sentinel MCP or Log Analytics results must
carry `querySha256` for the exact persisted source query; `record-runtime-validation`
blocks missing or stale bindings. A validation stage can pass as runtime
validated only with complete current-hash Sentinel and Advanced Hunting reports.
Authoring may explicitly record `runtimeStatus=environment-blocked` when no
current exact-query KQL/runtime failure exists; this is not runtime
qualification. Qualification cannot use that exception.

When investigating table/schema uncertainty, use standard-table documentation,
provider query schemas, and solution-owned parser or custom connector DCR/table
metadata. Do not invent schema or defer tool-owned repository/provider research
to the customer. Present scoped evidence and proposed assumptions for explicit
user accept/reject; stale source or query evidence requires re-review.

Unavailable workload tables are blocked environment results. Zero rows prove
query execution, not behavioral parity. Entity mappings require review.
For custom-detail bindings, verify the target output schema even when zero
rows are returned. Imported successful runtime results must include the actual
target-query `schema` array when custom details exist; a column count alone
cannot prove bindings. Runtime value size remains unverified by schema alone.

Defender Advanced Hunting and Log Analytics workspace queries are distinct
surfaces. A table visible in one does not prove availability in the other.
Always name the failing surface and use only the persisted workspace for
Sentinel validation.

For Authoring, structural success with an environment-only runtime gap may
complete this stage as passed with `runtimeStatus=environment-blocked`; preserve
the exact error and do not claim runtime qualification. This allows V3.1 package
creation. Qualification keeps the same gap blocking because deployment, mock
ingestion, and parity require the selected lab environment.

### Packaging

Use V3.1 for solutions containing XDR Detections:

```powershell
sentinel-xdr-migration package-v3-1 `
  --solution ".\Solutions\<solution>" `
  --version-bump none
```

V3 is the legacy Sentinel-only packager and intentionally skips XDR
Detections. Use `none` for repeat checks. Use an approved `patch`, `minor`, or
`major` action once when preparing the submission package; it synchronizes the
solution data and metadata versions.

Require the generated template, UI definition, parameter file, versioned ZIP,
AR/CD count matching, correct `E5Flavor` conditions, disabled CDs, unique IDs,
and explained validation results. Complete the packaging stage only with
`packager=V3.1`, the generated `packaging.v3_1.json`, and its template, UI,
parameters, and ZIP paths. Existing package files are not current-run evidence.
Do not relabel historical V4 evidence. Rebuild with V3.1. Surface missing
customer usage attribution warnings; optional `trackingId` must be copied
unchanged from Partner Center into SolutionMetadata.json, never synthesized.
V3.1 copies only the first authored tactic and its compatible nested techniques
into the ARM payload, without changing the complete YAML/provenance. Disclose
this intentional classification loss; packaging is not classification/alert
parity validation and must not mark parity passed.

### Deployment — qualification only

Deploy every reviewed AR and CD disabled. Verify Azure RBAC and Microsoft Graph
scopes separately. A successful write without live read verification is
blocked, not passed. Never infer Azure resource permissions from Entra Global
Administrator.
Direct Microsoft Graph deployment still requires at most one tactic; the
verified service rejected multi-tactic requests. Multi-tactic authored YAML can
pass structural validation but is not direct-Graph-deployment-ready. Never
silently truncate it outside the V3.1 ARM packaging boundary or infer that ARM
packaging proves live service acceptance.

### Mock ingestion — qualification only

Use `sentinel-solution-optional-testing` for this stage:

1. Run read-only workspace, DCR, Sentinel query, and effective ingestion
   permission preflight before fixture preparation.
2. Present Continue, Retry permission check, or Cancel. Continue is not write
   approval.
3. Check the default rule-specific `mock.json` path first.
4. Reuse a complete reviewed scenario or invoke
   `sentinel-solution-mock-data-generation`.
5. Require reviewed input for joins, thresholds, aggregation, sequences,
   historical baselines, watchlists, anomalies, and absence-of-data behavior.
6. Require separate exact-scope approval immediately before ingestion.
7. Group compatible rules by source table and supported ingestion path, then
   ingest each shared `mock.json` exactly once.
8. Track ingestion acceptance and query visibility independently.
9. Run the exact AR and CD queries over the same unique scenario markers and
   require identical matching source-row keys before alert parity.

Each AR/CD pair owns one shared `mock.json`; separate AR and CD payloads are
prohibited. `mock.json` may contain multiple correlated records when the
detection requires them. Never create a recurring ingestion job, and never
redirect an unsupported native table to a custom lookalike table. Use a
documented native telemetry generator or mark the rule blocked.

Every payload needs a unique scenario marker and expected malicious match-key
set. Pass only after ingestion is accepted and both exact queries observe the
same marked records. The existing alert-parity stage then compares alerts from
that same one-time ingestion.

For supported Standard tables, the scenario generator writes
`ingestion-contract.yaml` from the reviewed registry under
`Tools\AzureMonitorLogsIngestion\contracts`. Apply the locked workspace at
runtime:

```powershell
azure-monitor-logs-ingestion run `
  --contract "<scenario-folder>\ingestion-contract.yaml" `
  --workspace "<locked-workspace-arm-id>" `
  --payload "<scenario-folder>\mock.json" `
  --report "<versioned-report-path>"
```

The connected agent must execute generation, provisioning, ingestion,
visibility checks, exact row parity, alert parity, evidence updates, and
cleanup as one user-facing operation. Do not hand intermediate commands or
path discovery back to the user.

### Alert parity — qualification only

Use `start-alert-parity-batch` with a plan covering every converted detection:

1. Verify all ARs and CDs are disabled.
2. Enable all reviewed pairs.
3. Reuse the already ingested shared `mock.json` records; do not ingest a
   second AR- or CD-specific payload.
4. Capture alerts for every pair.
5. Compare counts, match keys, severity, tactics, entities, decisive evidence,
   and benign controls.
6. Complete or abort so every rule is disabled after success or failure.

### Report

Run `sentinel-xdr-migration solution-report`. The JSON and HTML reports must
distinguish passes, review requirements, environment blocks, skipped checks,
and genuine failures.

## Safety and completion

- Never use production telemetry or a production workspace for qualification.
- Ask before interactive authentication.
- Do not bypass failed or blocked gates.
- Do not rerun a passed release packaging stage and increment twice.
- Keep detections disabled except during controlled parity.
- Authoring completes after packaging and reporting pass.
- Qualification completes only after all optional lab stages and reporting
  pass.
