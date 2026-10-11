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

### Authoring goal and capability boundary

The product goal is autonomous best-effort candidate generation for source
rules, followed by a human-reviewable batch in which reviewers can accept,
change, or exclude proposed mappings. This is a roadmap goal, not a claim that
the current CLI provides autonomous research or batch review orchestration.

Today, the deterministic converter emits only mappings supported by its
existing rules and records uncertain mapping assumptions as `reviewRequired`.
That uncertainty must not hide query parse/runtime failures or other technical
errors. A rule that cannot be represented as a deployable Custom Detection
must remain visible in diagnostics outside deployable YAML; it must not be
silently dropped or emitted as an invalid placeholder. Future accept/change/
exclude decisions may resolve mapping ambiguity, but acceptance is not proof
of alert parity, does not erase technical failures, and does not approve
packaging, deployment, or any cloud write. Existing review, validation,
disabled-by-default, and exact-scope authorization gates remain in force.

### Authoring

`Discovery -> Conversion -> Validation -> Packaging -> Report`

This is the ISV publishing workflow. It does not require a tenant, workspace,
deployment, mock ingestion, or alert-parity test.

#### Optional resumable full-inventory authoring

The CLI also provides a separate, explicit `--yolo` mode for durable local
full-inventory authoring. It requires a newly initialized run and an explicit
`authoring` or `qualification` profile; it never upgrades a legacy run. The
run-scoped contract freezes the complete recursive source-rule inventory,
including source and query hashes, and records per-rule conversion and
validation results. It reuses existing discovery, full-solution conversion,
and structural validation. It does not call runtime providers, package, deploy,
ingest, create a PR, or change the review/qualification gates.

Select and record the exact run ID returned by initialization for all later
commands; do not infer a run from timestamps:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "Solutions\<solution>" `
  --workflow-profile authoring `
  --version-bump none `
  --yolo

sentinel-xdr-migration workflow-yolo `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>"
sentinel-xdr-migration workflow-yolo-refresh `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>"

sentinel-xdr-migration package-v3-1 `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>" `
  --version-bump none
```

Refresh imports only existing provider reports with matching persisted query
hashes; it does not execute queries. The complete frozen inventory remains the
coverage denominator, including unprocessed, blocked, and suppressed rules.
`E` counts each rule with an unresolved error or suppressed disposition once;
shared provider failures are accounted separately. A stop is persisted when
more than 50% of the inventory is in `E` and cannot be cleared by improved
later results. The 80% migrated threshold is advisory only; it is not
packaging, PR, or Qualification authorization. Stale source/target hashes or
changed inventory stop processing rather than overwriting user content. See the toolkit README's
[YOLO authoring guide](../README.md#opt-in-full-inventory-yolo-authoring) for
the contract, exact coverage definitions, and evidence-export option.

For a YOLO run, `package-v3-1` uses the existing workflow state: validation
must pass and every rule in the complete inventory must clear technical and
explicit-review gates. It records fresh V3.1 report and artifact hashes; the
advisory coverage threshold never bypasses these gates. The initialization-
selected version action is consumed once. A retry may use `--version-bump none`
only after that action was consumed and the current package-input hash matches
the post-build identity recorded by the run. Changed inputs make the previous
package stale and require an explicit new bump choice. Every retry runs V3.1
again; an old report, package artifact, or V4 report is never relabeled as
current V3.1 evidence.

The same freshness rule applies to ordinary gated authoring and Qualification
runs. `workflow-status` reports `packageFreshness`; `workflow-next` points back
to packaging and sets `releaseActionRequired` when package inputs or artifacts
are stale. Status reads are read-only. After completing the normal conversion
and validation gates, explicitly select a new release action for the exact
current input identity, then package using that same action:

```powershell
sentinel-xdr-migration workflow-plan-package-release `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>" `
  --version-bump patch `
  --expected-package-input-sha256 "<current-package-input-sha256>"

sentinel-xdr-migration package-v3-1 `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>" `
  --version-bump patch
```

Choose `patch`, `minor`, or `major` explicitly; no action is inferred. The
expected hash must match current package inputs at selection time. A subsequent
input change invalidates that selection and requires a new explicit decision.
The selected action can be consumed only once for those inputs. If V3.1 fails
after consuming the version, retry with `--version-bump none` only when the
post-build input identity still matches. The old V3.1 report and all package
artifacts are retained as historical evidence before rebuilding. This lifecycle
does not waive technical or entity-review gates: unresolved `reviewRequired`
flags continue to block packaging.

### Qualification — explicit opt-in

`Discovery -> Conversion -> Validation -> Packaging -> Deployment -> Mock ingestion -> Alert parity -> Report`

This is optional internal or ISV lab testing. Before initialization, require
the user to explicitly choose **Authoring**, **Qualification**, or **Cancel**.
There is no default and no workflow state may be created while the choice is
missing or declined. A configured tenant or workspace does not imply consent.

Qualification requires an approved non-production tenant and workspace plus
one early, plan-bound request for the anticipated conditional validation and
qualification actions, followed by separate exact operation/batch approval
immediately before any environment write begins. The early request is not
authorization to execute writes.

After target lock and before Discovery, build the local scope plan and ask once
for the complete potential-action set. Repeat this request only when the
target, plan identity, included resource families, payload, count caps, or
cleanup ownership changes. Do not ask the same broad planning question again
at later deployment preflight when the bound plan is unchanged.

For the contributor-facing authoring sequence, local configuration, provider
boundaries, review decisions, V3.1 packaging, and pending orchestration
capabilities, follow the toolkit README's
[Contributor authoring guide](../README.md#contributor-authoring-guide).
That guide describes current deterministic CLI behavior separately from
autonomous MCP dispatch, cross-provider research, and interactive decision
experience, which are not implemented by this Python package.

### Solution-local target configuration

Qualification may use a credential-free `Solutions/<solution>/.env`, copied
from the placeholder-only `Tools/SentinelToXDRMigration/.env.example`. Replace
its two literal values, `AZURE_TENANT_ID` and
`SENTINEL_WORKSPACE_RESOURCE_ID`; never put credentials or shell expressions
in this file or real identifiers in the shared example. The strict parser
accepts only those assignments and does not source the file, expand variables,
or execute commands. The solution `.env` is Git-ignored and excluded from
package inputs and optional evidence exports. It is not read by Authoring, and
no global or process-environment target defaults are silently applied.

Inspect the selected solution before approving it:

```powershell
sentinel-xdr-migration doctor --solution "Solutions\<solution>"
```

For a new configured Qualification run, explicitly opt in to Qualification and
confirm the displayed target:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "Solutions\<solution>" `
  --workflow-profile qualification `
  --confirm-configured-target `
  --version-bump none
```

The workspace subscription is derived from its validated ARM ID. Only after
explicit target confirmation does the resolver verify `az account show` has
the configured tenant and derived active subscription, then issue a single
exact `az resource show --ids <workspace-arm-id>` request for the customer ID.
It never lists or scans workspaces. Authentication or exact-read failures stop
initialization; sign in separately to the approved identity and retry.
Explicit command-line values remain supported, but conflicts with `.env` fail
with an actionable error instead of silently choosing either value. Supplying
both `--tenant-id` and `--workspace-resource-id` is also explicit target
confirmation; the subscription is derived and the customer ID may be resolved
or supplied.

An existing locked Qualification run remains authoritative on resume. Changes
to `.env` cannot retarget it; a conflicting local value blocks resumption and
must use the existing explicit target diagnosis/repair contract. Local `.env`
does not store the derived customer ID; that resolved identity is persisted in
the locked run target after the exact read.

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
the complete locked target. Alternatively, after reviewing the per-solution
configuration above, use `--confirm-configured-target` instead of supplying
tenant/workspace values; the workflow derives the subscription and reads the
customer ID only from that exact approved workspace:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "<solution-path>" `
  --workflow-profile qualification `
  --confirm-configured-target `
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
The solution-local `.env` target file is separately Git-ignored and excluded
from package/evidence content.
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
Exception: a best-effort entity-mapping assumption that is explicitly marked
`reviewRequired` may continue through conversion, structural validation, and
read-only query/schema testing. Preserve the pending review finding and its
source/query hash binding. This is not a review acceptance and does not clear
other `needsReview` findings, technical errors, failed queries, or malformed
content. Do not pause a complete batch for an assumption-only mapping choice.
The later packaging gate continues to reject unresolved review flags; this
policy does not authorize package readiness, deployment, or parity claims.
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
files alone is not conversion coverage. This pilot does not introduce scoped
runtime/deployment qualification or a generic waiver. The global source-runtime
missing-schema whitelist is limited to `IdentityInfo` and cannot authorize
scoped conversion, deployment, or reuse of stale query evidence. See the README's
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
For an unsupported identifier with an available output column, choose the
best supported target mapping deterministically when possible, retain the
original output value in custom details, and mark the choice as pending review.
For example, `Host.FullName` can provisionally use the documented
`hosts.nameColumn` when no stronger supported Host identifier is available.
State that the mapping is an assumption, not equivalence. This assumption-only
review does not interrupt conversion or read-only query/schema tests; it remains
visible and blocks packaging/deployment until reviewed. Never invent a target
field or query output column, and do not let this exception waive any unrelated
error or review gate.
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

This disclosure does not create a general no-runtime completion mode. A
specific review acceptance is not runtime verification. Report unexecuted
checks as not run; keep failed, blocked, and unresolved-review results visible.
Do not complete an unmet stage, silently bypass it, or treat declined runtime
checks as an environment-only error. The Authoring exception below remains
unchanged; if its evidence cannot be obtained, report the unmet gate and pending
implementation rather than success.

Run structural validation. When runtime validation is authorized, validate
original Sentinel and converted Advanced Hunting queries. Prefer capabilities
actually advertised by the official Sentinel Triage MCP; do not invent tool
names. Verify the exact persisted workspace/tenant and read permissions before
live queries. If a provider-level failure interrupts a query family, rerun the
entire family through the native Azure Monitor Query SDK for Sentinel
(`validate-sentinel-sdk`) or Microsoft Graph for Advanced Hunting, and record
the provider gap with complete-family evidence. The SDK uses the selected
Qualification run's locked workspace and current Azure CLI identity, sends the
exact source KQL as a request value, and does not impose a separate timespan.
It verifies the active CLI tenant and subscription against the locked target
before querying, then pins AzureCliCredential to the locked tenant only; it
does not pass `--subscription` to token acquisition because Azure CLI rejects
combining it with `--tenant`, and it never changes the active account.
Never mix providers within one family, and never fall back on a real KQL
semantic/runtime error. The legacy `log-analytics-cli` import remains
supported for externally executed evidence.
Keep structural, runtime, schema-binding, and qualification results separate.
`runtime-validation.graph.json` binds every result to the SHA-256 of the exact
Advanced Hunting query. Imported Sentinel MCP or Log Analytics results must
carry `querySha256` for the exact persisted source query; the SDK runner binds
it automatically and `record-runtime-validation` blocks missing or stale
bindings. A validation stage can pass as runtime
validated only with complete current-hash Sentinel and Advanced Hunting reports.
Authoring may explicitly record `runtimeStatus=environment-blocked` when no
current exact-query KQL/runtime failure exists; this is not runtime
qualification. Qualification cannot use that exception.

The source-runtime missing-schema whitelist is global across solutions, source
queries, and runs, and contains exactly `IdentityInfo` (case-insensitive
matching; canonical report name `IdentityInfo`). It automatically classifies
only a current Sentinel/Log Analytics source result with HTTP 400,
`failureKind=query`, and `SEM0100` explicitly stating that the `IdentityInfo`
table could not be resolved. This includes the preserved Azure Monitor SDK
error structure/message (`'summarize' operator: Failed to resolve table or
column expression named 'IdentityInfo'`) and the equivalent explicit
`Failed to resolve table 'IdentityInfo'` wording already present in provider
evidence. A missing column, another table, mixed/multiple error codes or
diagnostics, partial family/provider failure, authentication/authorization,
tenant, transport, timeout, stale query hash, or changed inventory is not
whitelisted. The classifier is structure-aware and source-provider-only.

There is no per-run allowlist, actor, reason, or acceptance command. The
derived runtime assessment is bound to each exact current source-query hash
and the complete source family. It does not create or mutate a decision
artifact: the raw source result remains `failed`, with its original provider
error. A qualifying result is represented as `source-waived`, never passed,
successful, or executed, and reports include both the whitelist table/reason
and the unchanged raw failure.

The whitelist only classifies source missing-table failures. Validation may
complete as `runtimeStatus=source-waived` only when every other current source
query passes, every converted XDR query has exact successful execution and
actual output-schema evidence (including verified `customDetails` bindings),
and full-solution structural, technical, and review gates pass. Direct stage
completion enforces those gates independently. A source-waived query alone
never completes Validation when XDR is unrun, has missing schema, or any
unrelated gate remains. Whitelist status remains visible in reports while the
overall Validation stage is blocked. No XDR schema, mapping review,
technical validation, packaging, deployment, ingestion, or parity gate is
weakened. Documentation that `IdentityInfo` exists in Advanced Hunting does
not establish availability in a selected Sentinel source workspace.

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

When the solution worktree does not contain the current V3.1 tooling, select
the approved toolkit checkout explicitly. The solution remains the source and
output root; the selected toolkit supplies the entry point, helpers, templates,
and validation contract. Omit `--toolkit-root` for the existing same-repository
behavior:

```powershell
sentinel-xdr-migration package-v3-1 `
  --solution "<solution-worktree>\Solutions\<solution>" `
  --toolkit-root "<toolkit-worktree>" `
  --run-id "<run-id>" `
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

### Advance deployment-scope planning and consent

In Qualification, produce and review a deterministic, local deployment-scope
plan immediately after target lock and before Discovery. This is the single
advance-consent request for the anticipated conditional qualification plan.
Refresh and display it during later preflight, but do not re-ask for unchanged
scope. The plan binds to the explicitly selected Qualification run and its locked
`qualification-target.json`; it does not read a new target, authenticate,
discover resources, or call Azure. The solution-local `.env` is only an input
to the existing target resolver. It is not authentication, consent, or a
retargeting mechanism, and it is excluded from source/package fingerprints.

`preflight-deployment` exposes additive `deploymentPlanning` metadata. To
persist the standalone plan and obtain its current `planSha256`, use:

```powershell
sentinel-xdr-migration plan-deployment `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>"
```

This command is local-only and writes `deployment-scope-plan.json` under the
selected run. Review the exact target, manifest-declared content counts and
workflow identities alongside raw source-file counts and unlisted files,
current reviewed disabled drafts, recursively unique source-rule identities,
eligible maximum additional Custom Detections, exclusions, content/package
hashes, component resource types, package selections, ingestion payload plan,
and scope caps. For playbooks, distinguish manifest-declared deployment
templates from actual Logic Apps workflow resources; parameterized names in
different templates are separate workflow resources. The plan distinguishes
ineligible new-conversion candidates
from matching current reviewed drafts: a candidate-generation limitation does
not invalidate a current reviewed draft whose persisted disabled Graph payload
and explicit projection validate. The eligible maximum is an upper bound, not
a promise that every rule converts or is deployable.
If there is no current package or reviewed ingestion plan, the affected plan
portions remain provisional. Unknown counts, costs,
retention, schemas, payloads, routes, or resources do not become blanket
approval.

Planning consent is an explicit, separate local decision. It is bound to the
current `planSha256`, exact locked target, selected component resource types,
included resource families, count caps, and package resource inventory. Record
the complete selected component set only after reviewing the plan:

```powershell
sentinel-xdr-migration review-deployment-plan `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>" `
  --expected-plan-sha256 "<planSha256-from-plan-deployment>" `
  --actor "<reviewer>" `
  --approve-component sentinelAlertRules `
  --approve-component xdrCustomDetections `
  --max-additional-custom-detections <reviewed-cap>
```

At the initial request, present the complete action inventory for this exact
target and plan with no preselected answers:

| Potential action group | Scope to show before asking |
| --- | --- |
| Disabled Sentinel AR / Graph CD creation or approved updates | Exact source-rule IDs and reviewed drafts; separate AR, CD, and pair counts; additional-CD cap; rules remain disabled. |
| Conditional fallback DCR and DCE creation | Exact contract, stream, destination, and candidate IDs/types; only if no compatible existing solution DCR is proven; DCE only if selected or required. |
| Conditional custom-log table creation | Exact table/schema/path/column count; only if the contract proves the table absent. Never alter an incompatible existing table. |
| Mock telemetry ingestion | Shared payload hash, record/batch counts, destination/table, stream, marker/timestamps, schema/transform/contract hashes, estimated bytes/cost/retention; ingest once per AR/CD pair, benign controls separate. |
| Controlled alert parity | Exact pair IDs/count, proposed test window, enable/restore operation bounds, and completion/abort plan to restore both rules disabled. |
| Full-package installation and XDR registration | Current package identity/resource inventory and every selected package flag; distinguish installation/registration from package creation. |
| Explicitly owned cleanup/deletion | Exact resources, ownership evidence, deletion cap, and exclusions; pre-existing or unowned resources are never included. |

Offer structured, unselected choices: **Approve all currently bounded and
available components**, **Select components**, **Revise the plan**, or
**Decline advance consent**. “Approve all” is an explicit user selection, not
a default. Persist only explicitly selected components that the current CLI
can bind to complete evidence. Unknown, provisional, unsupported, or
unselected components remain unapproved; revise or defer them rather than
treating unknown scope as unlimited. Denial or absence must not block
independent read-only checks or offline Authoring.

Sentinel alert rules and Graph Custom Detections are a pair-first route and
must be approved together, disabled, with an explicit cap no larger than the
current eligible maximum. A later `fullPackageAcceptance` component is
separate and requires a current verified V3.1 package plus explicit values
for every current package selection flag. It covers full-package installation
and selected XDR installation/Content Hub registration, not just package
creation. Pair-first deployment and later package acceptance are distinct
routes; package files are not live deployments. Stored playbook, workbook,
connector, API, or connection definitions do not imply live instantiation or
enablement.

The current consent CLI supports only the component names documented below.
The planner reports `controlledAlertParity` as provisional with eligible pair
IDs and calculated enable/restore request bounds, but cannot persist parity
consent until a finite test window and complete batch fixture plan are bound.
`ownedResourceCleanup` is unsupported: no exact run-owned deletion inventory
or deletion executor exists. Neither category can be approved through
`review-deployment-plan`; do not invent component names or claim these actions
are preapproved. An earlier approval limited to DCR/DCE does not approve
ingestion, enablement, package acceptance, or cleanup.

Separate components are available for `mockTelemetryIngestion`,
`fallbackDcr`, `fallbackDce`, and `customTableCreate`. Ingestion approval
requires a reviewed run-bound payload and exact destination/stream, records,
batches, payload and schema/transform/contract hashes, marker/timestamps,
estimated bytes/cost, and retention impact. The same reviewed payload is
ingested once per AR/CD pair; benign controls remain separate. DCR/DCE are
conditional provisioning scopes supporting ingestion of locally generated
mocks; they are not required to generate mocks. DCE requires an explicit
selection and must be paired with the DCR component. A DCR fallback is
conditional on no compatible existing solution DCR being proven. The current
resolver checks registered exact resource-name candidates only; it does not
discover arbitrary solution-owned DCRs, so this limitation must remain
visible and an exact fresh check is still required before provisioning.

Custom-table creation is conditional only when the exact supported ingestion
contract proves the selected custom-log table absent and supplies its schema,
path, columns, and plan. A present incompatible table is blocked, not altered.
An existing compatible native table such as `CommonSecurityLog` means table
creation is not needed; never create a custom lookalike. Ingestion, table
creation, DCR/DCE provisioning, rule deployment, enablement, cleanup,
retention changes, role assignments, and identity/app-registration changes
remain distinct operation scopes. Planning consent does not authorize any of
them.

Consent is never inferred from absent/false/unknown metadata, workflow
continuation, a token or role grant, environment identity, example counts,
mock-generation hypotheses, or package selection. Changes to the locked
target, plan/content/package hashes, resource families, payload, selected
flags, or count caps require a fresh plan and renewed consent. Do not hand-edit
workflow state to simulate a review. Planning-consent denial or absence must
not block independent read-only checks or offline Authoring.

Separate the advance request from authentication, Entra admin consent,
permissions, role assignments, and resource-write approval. Identity and
access steps never imply resource consent. A changed target, resource family,
mode, payload, cap, package flags, or cleanup-ownership boundary invalidates
advance consent and requires a refreshed plan and explicit renewed selection.

Advance consent is not final execution approval. Immediately before each
bounded environment-write operation or batch, show its operation, locked
tenant/subscription/resource group/workspace, solution/version, exact
resources, actions/methods and count, plus current permission/readiness
evidence, and obtain explicit approval. One approval can cover the enumerated
batch; it need not be repeated for each underlying HTTP request. Pause for
approval if a write expands beyond the approved batch. Planning consent cannot
substitute for final approval, permissions, technical readiness, or deployment
evidence.

### Deployment — qualification only

Deploy every reviewed AR and CD disabled. Verify Azure RBAC and Microsoft Graph
scopes separately. A successful write without live read verification is
blocked, not passed. Never infer Azure resource permissions from Entra Global
Administrator.
The Microsoft Graph payload builder explicitly projects a multi-tactic authored
detection to its first tactic and retains that tactic's nested techniques.
Eligibility must come from validating this actual disabled Graph payload, not
from a stale authored-document readiness flag. Preserve source YAML and
provenance, and disclose omitted tactics/techniques with classification parity
not established. This API-payload projection is not permission to rewrite the
authored detection or claim semantic parity; package acceptance remains a
separate route and its live behavior requires deployment/readback evidence.

For package acceptance, use ARM validation or preview only where the resource
types and deployment features support it. Bicep extensibility imports do not
support `what-if` ([Microsoft Learn: unsupported deployment
features](https://learn.microsoft.com/en-us/graph/templates/limitations#unsupported-deployment-features));
do not pass or wait for a `what-if` result for that route. An ordinary ARM
preview cannot prove extension acceptance, and ARM template validation must
not be represented as validating extension behavior. The approved actual
deployment followed by readback remains required.

### Mock ingestion — qualification only

Use `sentinel-solution-optional-testing` for this stage:

1. Run read-only workspace, DCR, Sentinel query, and permission preflight before
   fixture preparation or ingestion. Report telemetry-write permission, DCR
   creation permission, conditional DCE creation permission, and conditional
   destination-table creation permission separately. Check DCE creation only
   when the selected route includes a DCE. This diagnostic preflight does not
   provision resources or grant write approval. An `unknown` or pending-review
   permission is not a grant. Missing write permission blocks the
   corresponding write, not independent read-only workspace, DCR, schema, or
   query checks. This preflight requires no fixture. Pass `--run-id` when the
   solution has multiple runs; omit it only when the run is unique.

   ```powershell
   sentinel-xdr-migration preflight-deployment `
     --solution "Solutions\<solution>" `
     --auth-method azure-cli `
     --run-id "<run-id>"
   ```

   It writes `qualification-dcr-preflight.json` under the selected run's
   `Logs/sentinel-xdr-migration/<run-id>/` and adds
   `dcrPermissionPreflight` to the top-level Graph report. A permission
   `ready` means effective permissions were inspected, not that ingestion or
   query validation succeeded; the preflight never authorizes a write. See the
   README's [preflight report contract](../README.md#qualification-mock-ingestion-dcr-selection)
   for fields and status values. Aggregate `blocked` identifies locked-target
   artifact or mismatch failures; resource-read status `unavailable` includes
   HTTP 401. The per-contract `resourceFingerprint` hashes the exact target,
   candidate DCE/DCR/table IDs, returned resource configuration/schema, and
   current resource states. `contractFingerprint` is the SHA-256 of the
   registered serialized contract; provenance is
   `registered-contract-resolver`, and candidate selection is
   `exact-contract-resource-names-only`. `resourceReadAccess` may be `ready`,
   `denied`, `unknown`, or `unavailable`; `targetVerification` may be
   `blocked`, `unavailable`, `confirmed`, or `not-checked`.
2. Present Continue, Retry permission check, or Cancel. Continue is not write
   approval.
3. Check the default rule-specific `mock.json` path first.
4. Reuse a complete reviewed scenario or invoke
   `sentinel-solution-mock-data-generation`.
5. Require reviewed input for joins, thresholds, aggregation, sequences,
   historical baselines, watchlists, anomalies, and absence-of-data behavior.
6. Prefer a DCR explicitly listed or referenced by the selected solution only
   when its deployed resource in the locked workspace is proven compatible
   with the exact shared fixture, public input stream, transform, destination
   table/schema, endpoint, and permissions. A packaged ARM reference alone is
   not proof that the resource exists. Do not confuse an internal DCR
   identifier with its public input-stream name or enumerate other
   workspaces. For Logs Ingestion API fallback, structured records must use a
   customer-authored `Custom-*` input stream and `transformKql` to map to a
   supported `Microsoft-*` output. Public table schema does not reveal a
   connector's internal parser or enrichment, and reserved/service-managed
   columns must not be assumed writable. If no solution-listed DCR is suitable,
   a supported contract may be used to author a separate, isolated DCR locally
   and provision it only in the approved non-production Qualification target
   after exact-scope approval. A DCE is needed for private-link ingestion or
   when the DCR has no ingestion endpoint; this repository's contract tool may
   provision an isolated DCE as part of its route, but DCE creation is not a
   universal API requirement. “Locally” means locally authored configuration,
   not a local ingestion service. Never modify an existing connector DCR or
   redirect a native table to a custom lookalike; use a documented native
   telemetry generator or block the test when no supported ingestion path
   exists. See the README's
   [DCR-selection policy](../README.md#qualification-mock-ingestion-dcr-selection).
7. Require separate exact-scope approval immediately before ingestion or
   provisioning any new DCR, any DCE included in the selected route, or table.
8. Group compatible rules by source table and supported ingestion path, then
   ingest each shared `mock.json` exactly once.
9. Track ingestion acceptance and query visibility independently.
10. Run the exact AR and CD queries over the same unique scenario markers and
   require identical matching source-row keys before alert parity.

**Implementation status:** The solution-first DCR preference is the intended
policy, but the current registered-contract resolver checks contract-specific
resources in the locked target and does not yet discover or prefer a
solution-referenced DCR. Do not claim automatic solution-DCR selection; report
only compatibility and permission results actually established by the
available preflight and resolver.

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
