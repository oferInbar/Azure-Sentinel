# Microsoft Sentinel to Defender XDR migration toolkit

This toolkit converts the analytic rules in a Microsoft Sentinel solution into
versioned Defender XDR Custom Detection YAML files.

## Requirements

- Python 3.11 or 3.12
- PowerShell 7 for V3.1 solution packaging
- Azure CLI for authenticated runtime validation and Qualification

Install the package with a supported Python interpreter:

```powershell
python -m pip install -e Tools\SentinelToXDRMigration
```

The package metadata and CLI enforce the supported Python range. If the active
interpreter is unsupported, select or install Python 3.11/3.12. Do not modify
toolkit source files as an environment workaround during a migration run.

## Protected implementation

The XDR Solution Manager treats its prompts, skills, migration backends,
packaging backends, schemas, tests, dependency metadata, workflow definitions,
safety gates, and capabilities as read-only during solution migrations.
Runtime, environment, conversion, validation, packaging, or deployment
failures must be reported rather than repaired by changing toolkit source.

The XDR Solution Manager can never perform implementation changes, regardless
of who requests or approves them. Agent and backend development must be done
manually or through a different development agent. The XDR Solution Manager
remains limited to migration artifacts, packaging, validation, Qualification,
and routed reports.

The first milestone intentionally stops before ARM generation. It creates and
validates:

```text
Solutions/<solution>/
  Analytic Rules/
    <rule>.yaml
    Execution/
      <nested-rule>.yml
  XDR Detections/
    <rule>.yaml
    Execution/
      <nested-rule>.yml
  Logs/sentinel-xdr-migration/<run-id>/
    run.json
    workflow-state.json
    manifest.json
```

### Recursive source layout

Discovery includes `.yaml` and `.yml` files (case-insensitive extensions) at
every level of `Analytic Rules`, or the legacy `Analytics Rules` directory.
Conversion preserves each filename and its relative directories under
`XDR Detections`; same-named rules in different folders remain distinct.
Inspection, validation, runtime plans/results, deployment, parity, and reports
use the same recursive inventory. Runtime result `detection` values and parity
selectors use slash-separated paths relative to `XDR Detections`, for example
`Execution/Rule.yaml`. Parity's legacy filename/stem selectors are accepted only
when unambiguous. The shared mock-scenario generator also discovers nested
AR/CD pairs and accepts relative paths; source IDs disambiguate same-named rules.

Persisted manifest results use solution-relative `source`/`output` fields and
portable `sourceRelativePath`/`outputRelativePath` fields.
Use the latter output references in solution data's `XDR Detections` array;
the V3.1 packager already accepts nested paths. Only detection YAML is generated
under `XDR Detections`; reports/configuration remain in ignored solution `Logs`.

Existing flattened or relocated detections identified by source provenance are
reported as conflicts, even with `--overwrite`. Review and explicitly reconcile
or relocate these files before converting; the converter does not silently
duplicate, move, or delete them. Unidentified flat files with a colliding basename
also require review. Symlink content paths and escaping relative references are
rejected. Existing independent XDR release versions and overwrite rules are
unchanged.

Each XDR Detection YAML contains:

- an independent top-level content release `version`, initially `3.1.0`;
- the properties required to generate a
  `Microsoft.Security/detectionRules` resource;
- a disabled-by-default lifecycle state;
- converted KQL;
- optional top-level `requiredDataConnectors`, copied from source authoring
  metadata and never emitted as Graph/ARM detection-rule properties;
- translated entity mappings;
- all source MITRE tactics, in source order, with compatible techniques;
- a `contentProvenance` block linking the detection to its source analytic
  rule and recording conversion warnings.

The YAML contract is defined in
[`schema/xdr-detection.schema.json`](schema/xdr-detection.schema.json).

### MITRE authoring and deployment contracts

Conversion preserves every source tactic in order in
`properties.detectionAction.alertTemplate.tactics`, including two or more
entries. Multiple tactics alone are not an error or a `needsReview` reason.
Each entry contains only compatible source techniques/subtechniques. The
converter reuses the repository Sentinel validator's
`.script/tests/detectionTemplateSchemaValidation/Models/ModelValidationAttributes/KillChainTechniquesHelper.cs`
catalog and its base-technique matching semantics for subtechniques; this
catalog does not independently verify that a particular subtechnique suffix
exists. Source tactic identifiers are retained as target tactic strings, not
paired by position with the flat technique list. A technique shared by several
documented tactics can appear under each of those tactics, never under an
incompatible one. A tactic with no compatible techniques is retained without
inventing any. Unknown tactics, malformed IDs, unmatched techniques, or an
unavailable catalog remain blocking conversion/validation errors.
The Graph `mitreTactic.tactic` reference defines a string, not a public enum.

Original source lists remain independently preserved in
`contentProvenance.conversion.originalTactics` and `originalTechniques`.
Existing `ruleOverrides.<source-id>.tactic` plus `techniques` now correct only
the techniques of that named source tactic. They never narrow the list or
change source order; conversion emits an explicit legacy-override warning.
The tactic must already occur in the source, and techniques must be compatible.
An absent tactic, missing technique list, or invalid/incompatible override is
a blocking error, not a silently ignored decision. To change source tactic
intent, use the separate reviewed source-authoring process. Existing drafts
are refreshed only with the normal explicit overwrite approval.

**Authored YAML is not the deployed payload.** V3.1 ARM packaging copies only
the first tactic entry, including its compatible nested techniques, into the
deployment payload; it does not modify the multi-tactic YAML or provenance.
This is intentional classification loss, not validated classification or alert
parity. Direct Microsoft Graph deployment remains restricted to at most one
tactic because the verified service rejected multiple tactics with HTTP 400.
The direct deployment path fails instead of truncating or sending an illegal
multi-tactic payload. `deploymentReady` counts and per-result
`directGraphDeploymentReady` exclude authored multi-tactic documents even
when conversion and authoring structural validation pass. No runtime or
deployment success is inferred from authoring or packaging.

### Source-derived detection identity

Generated `properties.id` is the **full original Sentinel analytic rule template
GUID**, exactly as recorded in `contentProvenance.source.id`. It is not a deployed
Sentinel rule instance ID, a name slug, or an eight-character prefix. Renaming a
rule does not change this ID; distinct full source GUIDs remain distinct.
Source IDs must use the hyphenated GUID format; their case is preserved.
Duplicate source GUIDs (including case variants) and existing output ID or
provenance conflicts block conversion rather than overwriting another rule.

After reviewing local edits, explicit `convert --overwrite` can migrate the
converter's old `xdr-<name>-<first-eight-source-ID-characters>` IDs **only for the
same source ID and source path with converter provenance**. The independent XDR
version is preserved and the detection remains disabled. An existing custom ID,
missing/conflicting provenance, or a relocated output requires explicit manual
reconciliation; `--overwrite` is not permission to replace unrelated content.
The legacy ID must be reproducible from the stored display name or current source
name; an unrecognized name-based ID also requires manual reconciliation.
Without `--overwrite`, changed output is a conflict. Source YAML is never edited.

An ID transition persists `contentProvenance.conversion.identityChange` and an
actionable warning in the YAML and conversion manifest/report; later conversions
retain that warning. This is a **local artifact change only**, not evidence of
cloud migration. No existing cloud rule is updated or deleted by conversion.
Review/reconcile deployed identities before a separately approved deployment,
which otherwise targets the new GUID rather than the old name-based ID.

Structural validation and packaging require exact source/target ID equality for
documents declaring Microsoft Sentinel / AnalyticsRule provenance or the
`sentinel-to-xdr-migration` converter. They do not impose this GUID identity
contract on unrelated Custom Detections. The packager carries the GUID through
to the inner ARM `detectionRule.properties.id` and optional content registration;
the existing `[if(true(), '<GUID>', '<GUID>')]` literal expression is unchanged.
Graph payload preparation also preserves the validated GUID unchanged.

### Entity mapping and schedule diagnostics

Conversion follows the documented [Graph entity mapping contracts](https://learn.microsoft.com/en-us/graph/api/resources/security-entitymappingconfiguration?view=graph-rest-beta)
and [Sentinel source identifiers](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference).
In addition to Host, Account, IP, URL, AzureResource, CloudApplication, Mailbox,
and MailMessage, direct mappings include:

| Sentinel identifier | Graph collection and field |
| --- | --- |
| DNS.DomainName | `dns.domainNameColumn` |
| File.Name | `files.nameColumn` |
| MailCluster.Query / Source | `mailClusters.queryColumn` / `sourceColumn` |
| RegistryValue.Name | `registryValues.valueNameColumn` |
| SecurityGroup.DistinguishedName / SID / ObjectGuid | `securityGroups.distinguishedNameColumn` / `sidColumn` / `objectIdColumn` |
| FileHash.Value with query-proven constant Algorithm=SHA1 or SHA256 | `files.sha1Column` or `sha256Column` |

The hash proof accepts constant assignments in a simple single-table
`where`/`extend`/`project` pipeline, not an algorithm guessed from a column name.
Unknown/mixed algorithms, MD5, missing output columns, dropped fields, and
conflicting source identifiers remain warnings. Linked entities such as
DNS.DnsServerIp, RegistryValue.Key, File.FileHashes, and Process.ImageFile are
not scalar query-column mappings. No joins or synthetic fields are introduced.
Graph processes accept hashes, not Sentinel ProcessId/CommandLine; those source
fields remain unmapped. Graph's Amazon, Google Cloud, and OAuth collections do
not establish corresponding Sentinel source identifiers, so the converter does
not invent those mappings. These are converter limitations, not claims that
Defender lacks the entity type. The required Host/Account/Mailbox/IP asset gate
is unchanged.

### Supplemental entity evidence in custom details

Whenever source entity information lacks an equivalent final entity mapping,
the converter also binds the original output value under
`properties.detectionAction.alertTemplate.customDetails`. This applies to every
entity family, unsupported identifiers, ambiguous repairs, conflicting mappings,
and identifiers omitted by an explicit `ruleOverrides.<id>.entityMappings`.
For example, a reviewed `hosts.nameColumn: HostName` plus IP mapping can retain
the original Host.FullName value as `customDetails.HostFullName: DeviceName`.
It does **not** map arbitrary FullName values to `nameColumn`, replace valid
entities, remove mapping warnings/reviews, or claim restored identity,
correlation, semantic equivalence, or alert parity.

The [Graph `alertTemplate` contract](https://learn.microsoft.com/en-us/graph/api/resources/security-alerttemplate?view=graph-rest-beta)
defines each custom-detail value as a **query output column name**, not an event
literal or entity object. Its
[`alertCustomDetails` resource](https://learn.microsoft.com/en-us/graph/api/resources/security-alertcustomdetails?view=graph-rest-beta)
is an open key-value object. Source `customDetails` and per-rule override
`customDetails` are merged, with the same configured/catalog column renames as
converted KQL. Identical bindings are retained; a conflicting explicit key
blocks conversion without overwriting the source value. Malformed declarations
remain errors. Empty source objects remain empty when no supplement is needed.

Automatic keys concatenate the entity type and source identifier using
alphanumeric characters, for example `HostFullName` or `ProcessCommandLine`.
Existing keys are never overwritten. A collision uses `_2`, `_3`, and so on
in source mapping order; an existing detail for the same output column is reused
instead of duplicated. Repeated conversion is deterministic. Query-proven
equivalent mappings, such as an intact FullName decomposition into host name
and DNS domain, need no redundant supplemental key.
`contentProvenance.conversion.supplementalEntityDetails` records source entity
index/type/identifier, original and converted column, selected detail key, and
availability status. The actual detail bindings are normal Graph/ARM alert
properties; this provenance remains outside deployment properties.

Existing conservative KQL helpers distinguish known output columns, known
missing columns, and runtime-binding-pending output. Automatic bindings are
not emitted for projected-out columns or unproven destructive projections;
warnings and provenance explicitly record unpreserved information. The
converter never rewrites KQL to restore missing columns. Explicit source
bindings to missing columns are retained for correction but fail validation.
When output availability cannot be proven, a supplemental binding is labeled
`runtime-binding-pending`, with an explicit warning rather than an availability
claim. Runtime plans include `customDetailBindings`. Graph runtime validation
checks every binding against the returned schema. Imported successful runtime
results for detections with custom details must include the target query's
`schema` array (`name` or `Name` per column); a count alone is blocked, and a
missing bound column fails validation. Query execution alone does not establish
detail binding or entity correlation.

The [documented Defender limits](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#add-custom-details)
are **20 key-value pairs per rule** and **4 KB combined custom-detail keys and
runtime values per alert**. More than 20 authored pairs or keys alone exceeding
4 KB is a blocking error; nothing is silently truncated. The public references
do not specify a separate per-key character limit, so none is invented.
Runtime event-value size cannot be established from column names or schema:
the converter warns that the service drops the whole custom-details array if
the runtime limit is exceeded. Schema success is not proof of value-size safety;
qualification must check actual values.

`contentProvenance.conversion.informational` and manifest result
`informational` are optional string lists for nonblocking explanations of
preserved equivalents. They do not set errors, review reasons, or `needsReview`.
For example, Host.FullName is informational only when a conservative query proof
shows that retained HostName and DnsDomain explicitly decompose that same value
using the `iff`/`substring`/`indexof` pattern. Merely having name/domain columns
is not proof. Reassignments, branches, conflicting values, and unknown shapes
retain a warning; no unsupported `fullNameColumn` is emitted.
The identity proof also permits `summarize` when the full name survives as a
bare grouping key; previously derived name/domain columns must likewise survive
unchanged if reused. Aggregate values and computed grouping keys do not prove
identity equivalence. Native-table schedule classification is independent of
that identity proof: comments and aggregation do not hide a known native
lookback, but aggregation still cannot establish equivalent time windows.

Schedule messages record source frequency/lookback and emitted target frequency
with a [public lookback reference](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#lookback).
Native Defender fixed lookbacks are 4 hours for hourly rules, 12 hours for
3-hour rules, 48 hours for 12-hour rules, and 30 days for daily rules.
Information requires matching frequencies and configured/native lookbacks,
plus provably equal explicit event-time bounds in a simple native-table
pipeline. A duration in a comment or string is not a time filter.
Different lookbacks remain warnings even when an event-time filter is narrower:
that filter does not configure Defender's ingestion lookback.
Sentinel-only/custom, mixed, unknown, NRT, and ambiguous time-basis cases remain
warnings; a custom Sentinel lookback is never assumed when absent from the
payload. Assessment does not add filters, synthesize Timestamp, alter the
schedule, or claim alert parity, initial-run equivalence, or ingestion-delay
equivalence. Existing query conversion and human-review gates remain in force.

## Content-creator authoring policy and pending implementation

This section records the approved authoring policy and its implementation gaps.
It does **not** introduce a validation mode, waive an existing gate, or assert
that a schema resolver is implemented. The canonical
[workflow](agent-workflows/end-to-end-migration.md#validation) still governs
stage completion.

### Schema responsibility and evidence

For authoring, assume that tables referenced by the source Sentinel rule are
expected to be available in XDR. Do not ask the content creator whether the
target resolves both tables or directory fields. This is an authoring premise,
not a guarantee about any deployment environment, onboarding, licensing,
permissions, data freshness, or populated columns.

The tool is responsible for resolving standard Defender and Sentinel schemas
through an **actually advertised official schema MCP/API capability**, when
authorized and available, or authoritative Microsoft documentation. It must
identify the source and target query surfaces and resolve columns in their
table/alias scope; it must not ask customers to supply `Timestamp` versus
`TimeGenerated` or the casing of `AccountUPN`. Public documentation can support
schema review without accessing a tenant; it does not prove runtime execution.
Never invent an MCP capability or initiate authentication/runtime queries after
the user has declined live validation.

For `_CL` tables, infer only from available, actual connector definitions, DCR
stream/output transforms, or table definitions. The suffix alone proves neither
columns nor types. Cite the evidence and distinguish **inferred from definitions**
from **verified against the applicable schema** and **runtime validated**.
Missing or conflicting metadata is a specific tool/evidence limitation, not a
reason to fabricate fields or ask the customer to guess. Resolve conflicts
before claiming a safe transformation.

### Repair metadata at both ends

Metadata inconsistencies are not resolved merely by copying them faithfully and
reporting an error. Within the approved content-authoring scope, the orchestrator
must repair unambiguous, schema-defined metadata errors in both the Sentinel
source and the corresponding XDR draft, then inform the user. This applies to
all metadata, not only connector dependencies. It is a source-authoring
maintenance step, **not** permission for the converter to edit Analytic Rules:
normal conversion remains read-only with respect to source content, and no
automatic repair engine is implemented by this policy.

Only mechanical corrections with one defensible interpretation may be made
without a further content decision. For example, when an AWSS3 entry contains
`datatypes: [AWSVPCFlow]` but lacks the schema-required `dataTypes`, rename that
key to `dataTypes` in the source, then explicitly refresh the corresponding
draft. Do not normalize valid connector IDs, data-type values, arbitrary
extension fields, order, duplicates, or absent/empty declarations. Conflicting
keys or values, ambiguous intent, tactic/technique choices, entity meaning,
identities, and release versions require an explicit decision; never invent a
resolution or copy platform-specific metadata across incompatible contracts.

1. Record the affected files, field paths, exact before/after values and schema
   basis. Preserve earlier reports and query hashes before replacing evidence.
2. Make the minimal approved source correction. Regenerate only the affected
   draft with the reviewed configuration and explicit overwrite approval; use
   `--rule-id` for an isolated repair so unrelated or deliberately deleted drafts
   remain untouched. Respect the [single-rule scope contract](#single-rule-conversion).
3. Check both declarations against their applicable schemas, their intended
   correspondence, unchanged KQL/identity/version/lifecycle, and unrelated-file
   hashes. Refresh conversion diagnostics through the existing tools, clearing
   only errors actually resolved; record the repair and checks in run evidence.
4. Tell the user what was repaired versus what remains unresolved, including
   affected files and before/after values. Reports must disclose their scope.
   Existing offline comparison pages and evidence exports remain historical
   snapshots unless explicitly refreshed; never pair old content with new hashes.
   Static metadata success does not make runtime checks passed: retain `notRun`,
   mixed-surface reviews, warnings, and all unmet workflow gates.

| Capability | Current implementation | Approved policy / pending work |
| --- | --- | --- |
| Standard schema resolution | `catalog.py` contains a finite table/rename catalog; `convert_query` applies token replacements. No general authoritative source/target schema resolver is implemented. | Resolve documented schemas and table-scoped lineage automatically; retain surface, source, and confidence evidence. |
| Mixed-query time columns | Native-only catalog queries may rename `TimeGenerated`; mixed native/passthrough queries preserve it and request review. | Resolve each reference against its actual table/alias, not a whole-query rename or a customer schema question. |
| Custom logs | `_CL` recognition identifies names, not a complete schema. | Infer only from actual available connector/DCR/table metadata; report missing/conflicting evidence explicitly. |
| Runtime validation declined | YAML generation is possible without runtime access; existing structural/review checks and workflow gates remain. No general no-runtime completion/waiver mode is introduced here. | Show the disclosure below and specific checks. Any new optional-validation state/gate behavior requires a separate implementation decision. |
| Entity equivalence | Documented identifier mappings and conservative proofs exist; unsupported mappings produce diagnostics. | Explain the exact retained identifiers, actual field loss, or proven equivalence; distinguish converter proof limits from target-contract limits. |
| Source connector dependencies | Optional top-level `requiredDataConnectors` is deep-copied unchanged and structurally validated. Graph and inner ARM properties exclude it. | Repair schema-clear inconsistencies in source and draft through the authoring step above, then inform the user; converter source inputs remain read-only. Target-specific dependency translation/registration remains separate pending work; source declarations do not prove deployment readiness. |

When runtime validation is declined, the review UI should say:

> KQL has not been validated because this migration runs without runtime validation. Enable full validation, or review/accept the specific migration checks below.

This is approved presentation policy, not a claim that an “Enable full
validation” control or a new acceptance mechanism exists. Continue reporting
actual schema/static results separately; do not relabel not-run, blocked,
failed, or `needsReview` results as success. Acceptance of a supported,
specific migration review item is not KQL execution, syntax verification,
deployment readiness, or alert parity. The existing Authoring
`runtimeStatus=environment-blocked` exception requires its stated evidence;
declining runtime checks is not that exception.

### Worked review: Local Admin Group Changes

The inspected source is
[`Analytic Rules/Persistence/LocalAdminGroupChanges.yaml`](../../Solutions/Microsoft%20Defender%20XDR/Analytic%20Rules/Persistence/LocalAdminGroupChanges.yaml),
rule `63aa43c2-e88e-4102-aea5-0432851c541a`. Its parallel generated XDR YAML
was reviewed locally on 2026-10-07; it was not regenerated or executed.
Generated artifacts can retain older warnings and are not evidence that a
current converter proof has run.

The official references distinguish these contexts:

| Table / surface | Documented fields relevant here |
| --- | --- |
| [IdentityInfo — Sentinel / Log Analytics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identityinfo) | `AccountUPN`, `AccountSID`, `AccountCloudSID`, `TimeGenerated` |
| [IdentityInfo — Defender Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table) | `AccountUpn`, `OnPremSid`, `CloudSid`, `Timestamp`; the unified schema also documents licensing/onboarding and UEBA-specific availability. |
| [DeviceEvents — Log Analytics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents) | `TimeGenerated`, `AccountSid` |
| [DeviceEvents — Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) | `Timestamp`, `AccountSid` |

These are **documentation-verified schema facts**, not tenant verification.
`AccountUPN` to `AccountUpn` is supported for this IdentityInfo surface
transition, not a universal casing rule. In the inspected output that rename
occurred, but `AccountSID` and `AccountCloudSID` remain in the IdentityInfo
branch, while both event projections retain `TimeGenerated` from DeviceEvents.
Those retained references do not match the documented target schemas; they are
specific unresolved migration checks. IdentityInfo's source `AccountSID` and
target `OnPremSid` describe the on-premises SID; `AccountCloudSID` and `CloudSid`
describe the cloud SID. Resolving those references must respect the existing
`OnPremSid` alias, not blindly rename every occurrence. DeviceEvents'
`AccountSid` already uses the documented spelling on both surfaces.

The `leftouter` SID join with `NewUsers` and `innerunique` SID join with
`ADAZUsers` exist in both source and output. Any pre-existing filtering or
correlation limitations are source behavior, not a newly introduced migration
bug unless conversion changes their semantics.

[Sentinel identifiers](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference)
are not interchangeable with the more restricted
[Graph host](https://learn.microsoft.com/en-us/graph/api/resources/security-hostentitymapping?view=graph-rest-beta)
and [Graph account](https://learn.microsoft.com/en-us/graph/api/resources/security-accountentitymapping?view=graph-rest-beta)
mapping contracts. Neither of these Graph mapping types documents a
`fullNameColumn`. For this rule:

- Host `HostName` and `DnsDomain` survive as `nameColumn` and
  `dnsDomainColumn`. The query explicitly splits the same `DeviceName` on its
  first dot, so the original host value is represented by that pair (including
  the no-dot case). The inspected artifact's Host.FullName warning must not be
  described as proven host-identity loss; the current conservative proof may
  still be unable to establish equivalence through this multi-branch query.
- Account `AccountName` and `laccountdomain` survive as `nameColumn` and
  `ntDomainColumn`, but they do **not** prove equivalence to `UserAdded` for all
  rows. When the NewUsers join has no match, `UserAdded` uses
  `DirectoryDomain\\DirectoryAccount`, while the mapped domain remains the
  unmatched `laccountdomain`. The directory-domain information carried by the
  source FullName mapping is not represented by the emitted account mapping
  on that branch. `UserAdded` remains in query output; it is mapping loss, not
  deletion of the query column. The retained SID joins themselves are unchanged.

### Connector dependency preservation and deployment boundary

For the same rule, source lines 8–12 declare
`MicrosoftThreatProtection` with data types `IdentityInfo` and `DeviceEvents`.
The inspected older generated artifact omitted this list. The correction is
implemented in the current working tree; existing artifacts are **not**
automatically rewritten. The source remains authoritative when explicitly
reconverting with the existing overwrite and identity safeguards.

```yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - IdentityInfo
      - DeviceEvents
properties:
  # Only supported detection-rule properties belong here.
  status: disabled
```

This is a partial authoring example, not a complete deployable detection.
Presence is significant: a missing source property stays absent; an explicit
`[]` stays `[]`. Entries, connector IDs, data-type spelling, order, duplicates,
and additional per-entry metadata are deep-copied without normalization.
Each entry must be an object containing a string `connectorId` and an array of
strings `dataTypes`; additional properties remain extensible. Nulls, scalar
lists, missing required members, and incorrectly typed members are invalid,
not silently dropped. At initial discovery, conversion retains malformed
metadata for review, records field-specific errors and `needsReview`, and
structural validation rejects it. It is never counted as successfully converted.
This preservation is not the final authoring outcome: follow
[repair metadata at both ends](#repair-metadata-at-both-ends) to correct
schema-clear errors in source and draft, or obtain a decision for ambiguous
conflicts, then report the repaired and outstanding findings.

1. [`build_xdr_document`](sentinel_xdr_migration/converter.py)
   validates source dependency metadata against the output field schema and
   deep-copies it into optional **top-level** `requiredDataConnectors`, parallel
   to the Sentinel authoring field. Source identity, provenance, independent
   XDR release version, and disabled lifecycle safeguards are unchanged.
   `conversion.requiredWorkloads = ["sentinel"]` remains separate and is not an
   equivalent connector/data-type declaration.
2. The [YAML schema](schema/xdr-detection.schema.json#L99) requires selected
   provenance members and now explicitly validates optional top-level
   `requiredDataConnectors`. This does not make it a deployment API field.
   Existing documents without the field remain backward compatible.
3. [`graph_detection_payload`](sentinel_xdr_migration/deployment.py#L184)
   copies only `document["properties"]` into the Graph request. The
   [Graph detectionRule contract](https://learn.microsoft.com/en-us/graph/api/resources/security-detectionrule?view=graph-rest-beta)
   does not document `requiredDataConnectors`; its absence from that payload is
   not evidence of a missing supported deployment field.
4. The packager
   [`customDetections.ps1`](../Create-Azure-Sentinel-Solution/common/customDetections.ps1#L451)
   similarly copies `properties` into the MicrosoftSecurity extension resource.
   Its registration path (lines 311–316) emits only
   `dependency.requiredWorkloads`. Neither path emits source connector metadata
   into a deployed detection. The authoring YAML is retained unchanged.
   In contrast, the Sentinel rule path in
   [`commonFunctions.ps1`](../Create-Azure-Sentinel-Solution/common/commonFunctions.ps1#L2675)
   explicitly retains `requiredDataConnectors`.
5. The official [Sentinel alert-rule-template API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rule-templates/get?view=rest-securityinsights-2025-06-01)
   documents `requiredDataConnectors` with `connectorId` and `dataTypes`.
   The official [contentTemplates ARM reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/contenttemplates)
   separately documents plural `dependencies` with `contentId`, `kind`,
   `criteria`, and `operator`, including DataConnector/DataType kinds. That is
   **not** the same contract as the packager's singular
   `dependency.requiredWorkloads`, and it does not justify copying Sentinel
   YAML fields into detection-rule properties. The attempted public
   [Microsoft.Security/detectionRules ARM reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.security/detectionrules)
   returned 404 during this review: an authoritative exact-version
   MicrosoftSecurity extension contract was not established. No claim of
   extension support or runtime rejection is made.

**Verdict:** the previously confirmed loss of source authoring dependency
metadata is corrected for subsequent conversions by the top-level field. No
unsupported Graph/ARM field was added, and existing detection YAML must be
explicitly refreshed before it contains the correction. This is not a schema
resolver, validation waiver, or deployment action.

The [connector metadata tests](tests/test_connector_metadata.py) cover present,
empty and absent declarations, extension fidelity, deep-copy isolation,
malformed input/structural rejection, explicit reconversion and independent
version preservation, and actual local packaging exclusion from both install
and registration wrappers. Graph payload tests verify exclusion and isolation.
Conversion report errors use the existing reporting path. Sanitized evidence
allowlists and report/UI contracts are unchanged; no raw connector extension
metadata is added to evidence exports.

A separate target dependency model remains a future design decision. Any content-registration propagation
must first be checked against the exact extension/registration API version and
translated to its documented contract, not copied blindly. Package generation
logic, source content, existing generated artifacts, runtime gates, and workflow
state are not changed by this correction.

## Safety model

Conversion is conservative. A file is still generated when manual work is
needed, but `contentProvenance.conversion.status` is set to `needsReview` and
validation fails until blocking issues are resolved. The tool never changes
files under `Analytic Rules` and does not modify `Package/mainTemplate.json`.

The `search` review check uses KQL tokens rather than a raw word match. Line
and block comments, quoted/verbatim/multiline strings, and ordinary column or
binding references named `search` do not request operator review. Executable
`search` at query/pipeline boundaries (including nested queries) still requires
review and retains the existing `needsReview` gate. This is a conservative
lexical check, not a syntax or semantic validator; runtime validation remains
required. Other KQL checks and explicit review-acceptance rules are unchanged.
Previously generated findings are not rewritten: review stale acceptances
before an explicitly requested reconversion.

Generated detections start with:

```yaml
properties:
  status: disabled
```

### Independent XDR release version

New detections start with `version: 3.1.0` even when the source Sentinel rule is
`1.x`. `contentProvenance.source.version` continues to record the actual source
version; neither that source file nor its release version is promoted.
The required XDR version is a `major.minor.patch` string in `[3.1.0, 4.0.0)`.
It is distinct from `schemaVersion: 1.0.0`, `properties.id`, the converter
version, and API/provider versions.

Regeneration preserves an existing valid XDR version (for example `3.1.1`)
when the output belongs to the same source rule, including with `--overwrite`.
An invalid existing version or different source identity is a conflict, not
permission to reset the release. Resolve it explicitly before reconverting.
Files from older converter runs without a top-level version fail structural
validation and V3.1 packaging with reconversion guidance. After reviewing any
manual edits, explicitly reconvert with `--overwrite` to initialize `3.1.0`,
or author the independent XDR version. Never rewrite source provenance.
Solution bumps do not bump detection versions; authors manage subsequent XDR
content releases independently.

### Local parser bindings

Conversion automatically renames local `let` bindings that match a solution parser's
`FunctionName` or `FunctionAlias`. The shared PowerShell packager applies the same
normalization before building both the CD installation and its registration, including
when it receives previously authored detection YAML.

Names use `__xdr_inline_<original>` with a numeric suffix when necessary. Microsoft's
KQL parser and semantic binder identify the declaration and its references, including
nested scopes. This is not a text replacement: columns, strings, comments, parameters
that shadow the binding, and native parser YAML remain unchanged. Repeated runs are
stable. Conversion reports each rename as a warning, not a review blocker.

The normalizer checks syntax, binding identity, and inferred column shapes after editing.
It fails explicitly when a safe rewrite cannot be verified, including wildcard-selected
bindings, `union withsource`, and implicit output-column name changes. Use explicit inputs
and column aliases in these cases. Missing tooling is a setup error, not permission to
skip normalization.

This offline check uses the parsers shipped in the solution, including nested `.yaml`
and `.yml` files. It does not discover unrelated functions installed in a target tenant,
inline missing parsers, or replace live schema/query validation.

Requires Node.js and the pinned KQL dependency. From the repository root:

```powershell
npm ci --prefix Tools\SentinelToXDRMigration\kql
npm test --prefix Tools\SentinelToXDRMigration\kql
```

## Install

```powershell
cd Tools\SentinelToXDRMigration
python -m pip install -e .
```

## First-run setup

Run the guided setup once:

```powershell
sentinel-xdr-migration setup
```

If tenant security policy blocks device-code authentication, use interactive
browser authentication:

```powershell
sentinel-xdr-migration setup --hunting-auth-method browser
```

Setup checks the local environment and launches authentication only when it is
needed:

- `az login` for original Sentinel query execution through Log Analytics;
- a one-time Microsoft Graph device-code sign-in for Advanced Hunting.

Authentication tokens are managed by Azure CLI and the operating system's
credential cache. The toolkit stores only an authentication record and
non-secret configuration under `~/.sentinel-xdr-migration`.

Inspect readiness at any time:

```powershell
sentinel-xdr-migration doctor
```

Persist an approved non-production workspace once for confirmation and reuse
across solution workflows:

```powershell
sentinel-xdr-migration configure-workspace `
  --tenant-id "<tenant-guid>" `
  --subscription-id "<subscription-guid>" `
  --workspace-resource-id "<workspace-arm-id>" `
  --workspace-customer-id "<workspace-customer-id>"
```

`doctor` returns both configured identifiers. Qualification still asks the
user to confirm the workspace for each new workflow, but it does not require
the ID to be re-entered.

Conversion and structural validation always remain available in offline mode.
Missing runtime access is reported explicitly and never blocks YAML generation.
For unattended inspection without opening sign-in prompts:

```powershell
sentinel-xdr-migration setup --non-interactive
```

The CLI setup covers Azure CLI and direct Microsoft Graph authentication. The
official Triage MCP is configured and authenticated in the agent host, not by
this Python package. For first use, configure:

```text
https://sentinel.microsoft.com/mcp/triage
```

Sign in with a supported tenant member identity and complete the tenant's
required Defender/Sentinel onboarding, consent, and security-reader access.
Guest identities may not work. The agent should verify that
`RunAdvancedHuntingQuery` is available before selecting Triage as its runtime
provider.

## Command line

### Single-rule conversion

For an explicitly reviewed pilot or isolated refresh, select exactly one source
analytic rule template GUID (not a deployed rule ID or filename):

```powershell
sentinel-xdr-migration convert --solution "<solution-path>" --run-id "<run-id>" --rule-id "<source-template-guid>" --config "<reviewed-config.json>" --overwrite
```

`--rule-id` accepts one full hyphenated GUID, matched case-insensitively while
preserving the source's spelling in generated identity. Repeated selectors,
malformed IDs, no match, duplicate matching source IDs, and a selected ID present
in `excludedRuleIds` fail before creating or changing outputs, reports, logs or
state. Reconcile a selected exclusion explicitly; selection never means deletion.
All source/output identities and provenance remain inventoried for collision
checks. Existing overwrite, independent version, review, connector-metadata and
source-provenance contracts still apply.

Only the selected rule's nested output path may be written. All unselected drafts
remain byte-for-byte unchanged, even with `--overwrite` and unselected config
exclusions. Without `--overwrite`, changed selected content remains a conflict.
Omitting `--rule-id` retains full-solution conversion, including its existing
explicit-overwrite deletion behavior for excluded outputs.

The selected run's `manifest.json` and transformation report are replaced, not
merged with earlier full-solution results. `scope.kind=rule`, `scope.ruleIds`,
`scope.sourceTotal` and `scope.selectedTotal` identify exactly what was attempted;
counts describe only that rule. Repeated pilots do not accumulate full coverage.
Structural `validate` still checks all existing detection files and exposes
`conversionScope`; valid files are not proof that all source rules were converted.
Previously passed conversion/downstream workflow stages become blocked, retaining
historical evidence; discovery and qualification target locks are unchanged.
Solution-stage success and the toolkit packaging entry point are blocked until
full-solution conversion and the normal validation/review gates are completed.
Conflicts/needsReview still return CLI exit code 1; invalid selection returns 2.
A successful scoped conversion is only local rule authoring, never full-solution
readiness, runtime validation or approval to deploy.

Scope evidence and guards are run-local, just like other workflow evidence;
content YAML remains shared across runs. Do not reuse another run's prior
validation/package evidence after changing shared content. The selector does not
introduce scoped packaging, deployment, runtime validation or a gate waiver.

### Solution-local reports and legacy resumption

All new reports, logs, workflow state, qualification target, migration
configuration, and captured runtime evidence belong in
`Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/`. All solution `Logs` folders
are Git-ignored. Do not force-add them: provider responses, error messages,
query/alert evidence, and lab identities may be sensitive. Optional curated
PR snapshots are described below. Tokens/authentication records and reusable
cross-solution onboarding configuration remain in the existing user credential
store; they are never copied into a solution. Shared synthetic sample catalogs
and reviewed mock fixtures retain their existing `Sample Data` locations.

Each run has a collision-safe UTC timestamp/UUID ID recorded in `run.json` and
workflow state. `workflow-init` resumes the sole existing run by default.
`workflow-init --new-run --workflow-profile authoring --solution "<solution>"`
explicitly starts an isolated workflow with a new ID. Runs do not copy another
run's configuration, reports, or stage results. Detection YAML and Package
content remain shared solution content; a new run does not snapshot those files.

Use `workflow-runs --solution "<solution>"` to list IDs. Every solution CLI
command accepts `--run-id "<id>"`. When multiple runs exist, omitting it fails
instead of choosing the newest run or stale evidence. A selected nonexistent ID
also fails, except when explicitly applying a migration preview. Python callers
can scope existing APIs with `artifacts.using_run(solution, run_id)`. Direct CLI
writers without a workflow create one run on first use and reuse it thereafter.

Status reads can fall back to prior flat solution Logs,
`Reports/<solution>/sentinel-xdr-migration/`,
the old `AZURE_SENTINEL_REPORTS_ROOT` location, and report files in
`XDR Detections`. Reads warn but never move state or initialize a new workflow.
Before the next write, review and explicitly apply the copy:

```powershell
sentinel-xdr-migration migrate-reports --solution "Solutions\<solution>"
sentinel-xdr-migration migrate-reports --solution "Solutions\<solution>" --run-id "<preview-run-id>" --apply
sentinel-xdr-migration workflow-status --solution "Solutions\<solution>" --run-id "<preview-run-id>"
```

The entire copy is preflighted for conflicts. Originals remain untouched;
`<run-id>/legacy-artifacts.json` records their hashes. The preview's `runId`
must be passed to apply to use that exact destination. The previous flat-Logs
ledger is honored: newer flat workflow state supersedes the archived root
Reports state only when the archived original still matches its recorded hash.
Unreceipted conflicts stop the copy. Migrated artifacts belong only to their
importing run, never to subsequent new workflows. Changed legacy copies or missing
migrated files block resumption rather than selecting stale evidence. Repeated
apply is idempotent. Reconcile conflicts manually; never discard or replace
blocked workflow state. Nonportable/credential-bearing migration configuration
requires explicit review rather than automatic KQL rewriting.

Persisted known filesystem references are solution-relative (including the
run ID for reports), with `/`
separators. The workflow packaging gate and summary report resolve these
against the selected solution; old absolute and repository-relative references
remain readable. Move/copy external evidence into the solution before relying
on portability. External machine paths and raw provider messages are not
arbitrarily rewritten; Logs are not a sanitized public export. Lab tenant,
subscription, and workspace IDs are retained to preserve qualification locks.
Known credential fields, bearer tokens, and signed URL values are redacted in
report serialization, but this is not a guarantee that raw provider payloads
are safe to publish. Source queries and detection YAML are never sanitized or
rewritten by reporting.

Content discovery excludes `Logs`, `Reports` and `Evidence` subtrees. Only detection YAML
belongs under `XDR Detections`; solution Data content arrays and Marketplace
ZIPs must not include runtime artifacts. The old report-root environment
variable is read-only compatibility input, not a new-output override.

### Optional PR evidence export

After a run is stable, explicitly export its public review snapshot:

```powershell
sentinel-xdr-migration export-evidence --solution "Solutions\<solution>" --run-id "<run-id>"
```

This local-only command needs no tenant, authentication or cloud-write approval.
It writes only `Evidence/<run-id>/evidence.json` and `summary.md`, relative to
the selected solution. These files may be reviewed and committed; raw `Logs`
remain ignored. Export is never automatic, does not rerun tests, does not
update reports/state/logs, and refuses any existing destination (including the
same run). Multiple runs require explicit selection; legacy flat reports must
first follow the normal report migration process. Evidence is never a runtime
input, resume source, solution Data content input or Marketplace ZIP input.

Schema `1.0.0` is a fixed allowlisted projection: all eight stage statuses and
attempt counts, profile/version-bump decisions, fixed conversion, structural,
three runtime-provider, V3.1 packaging, query-parity, alert-parity and solution
reports. Every result is retained, including failed, blocked, pending, not-run,
excluded and needs-review results; unfamiliar statuses become `unknown`.
Missing/invalid reports and unsupported fields are explicit. Historical baseline
decisions and command history have no supported contract and are marked
unsupported, not inferred from prose. The exporter records its real version,
Python version and normalized invocation, not invented historical commands.
Generated detection provenance supplies converter/content versions when available.

The summary header names the public solution folder (never its local parent
path), run, profile and recorded workflow status. Structured `solution` metadata
distinguishes the current version observed in `SolutionMetadata.json` and the
single `Data/Solution_*.json` from the requested version action. Missing,
invalid, conflicting or multiple-copy version inputs remain unknown. A requested
target version is not inferred from a bump: there is no supported persisted
target-version contract. In particular, current `3.0.18` plus requested `minor`
does not claim that `3.1.0` was packaged. The UTC `exportedAt`, exporter version
and Python version describe this export, not historical migration execution.
Identical inputs and the same export timestamp produce the same projection.
Older snapshots without export timestamps render them as unknown; filesystem
modification times and current run facts must not be substituted.
Explicitly authorized header-only enrichment of an older snapshot must preserve
all original results, hashes and exporter identity. Record a separate UTC
`headerUpdatedAt` and `headerRenderer`; if reading today's solution version, mark
`solution.versionObservation` as `header-update`, not `export`. The renderer
labels this new observation separately and keeps an unrecorded original export
time unknown. This does not enable overwrite/refresh in `export-evidence`.

Only a checked public solution title, enumerations, bounded counts, strict
version/timestamp strings, SHA-256 hashes and
checked solution-relative content references are exported. No raw messages,
errors, queries, alerts, records, URLs, provider responses, arbitrary stage
artifact values, IDs or unknown fields are copied. Unsafe references (including
symlinks, traversal, identifier/credential-like or unusual filenames) are withheld.
Hashes describe export-time bytes; source-query provenance mismatches are
explicit, but historical validation-to-content hash binding is unsupported.
Reported passes are **not independently verified or trusted attestations**.
Changing observed inputs during export aborts it; export only stable runs.

Review the snapshot before publishing: solution names and content filenames are public-facing
metadata, and no heuristic can recognize every secret embedded in an otherwise
ordinary name. Titles with URLs, paths, control/markup characters or recognized
identifier/credential patterns are withheld. Rename sensitive content through the normal authoring
process, never publish raw operational reports to compensate for omitted detail.
Unknown report filenames/contracts are not auto-discovered or copied.

### Resumable end-to-end workflow

The repository agent uses a gated workflow manifest. Before initialization,
the user must explicitly select `authoring` or `qualification`; the CLI has no
profile default. The `authoring` profile coordinates discovery, conversion,
validation, V3.1 packaging, and final reporting:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "Solutions\<solution>" `
  --workflow-profile authoring `
  --version-bump patch

sentinel-xdr-migration workflow-status --solution "Solutions\<solution>"
sentinel-xdr-migration workflow-next --solution "Solutions\<solution>"
```

Every packaging stage runs through:

```powershell
sentinel-xdr-migration package-v3-1 `
  --solution "Solutions\<solution>" `
  --version-bump none
```

The command invokes `V3/createSolutionV3_1.ps1` (V3.1) and writes
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\packaging.v3_1.json`. A packaging
stage cannot pass without that current-run V3.1 evidence and all generated
package artifacts.

Old V4 reports remain historical evidence; do not relabel them as V3.1.
Rebuild using `package-v3-1`. Package-version selection is unchanged, but V3.1
rejects effective solution and XDR release versions outside `[3.1.0, 4.0.0)`,
and other content-item release versions `>= 4.0.0`. Explicit bumps that select
an out-of-range version fail without overwriting package files or persisting
the bumped source version. These are release bounds, not ARM API/schema bounds.
XDR uses only its top-level YAML `version`, including when registration is
disabled. Registration metadata and content product IDs use that same version.
Data `XDR Detection Version`, solution version, and source provenance are not
fallbacks in V3.1. See "Independent XDR release version" above for older files.
Optional `trackingId` in SolutionMetadata.json is the complete Partner Center
customer usage attribution ID, not a bare GUID, Partner ID, or plan ID.
When absent/blank, V3.1 attempts anonymous **public Marketplace catalog/template**
discovery (not authenticated Partner Center API access) using exact publisher and
offer identity and one unambiguous plan/marker. It saves the validated full ID
into authoritative SolutionMetadata.json and emits the current marker shape.
Explicit IDs win without lookup. Set `SENTINEL_SKIP_ATTRIBUTION_LOOKUP=1` for
offline attribution; the CLI inherits it without an additional flag.
Lookup failures leave metadata unchanged and preserve prominent warnings in the
packaging report; successful provenance is recorded separately in
`attributionSources`. Local metadata write failures stop packaging.
Partner Center cannot auto-add tracking for functional nested deployments.
If lookup cannot resolve it, obtain the ID from offer > plan > Technical
configuration, add it, and rebuild. Missing attribution does not imply upload
rejection. See the [V3.1 guide](../Create-Azure-Sentinel-Solution/V3/README-V3_1.md)
and [official attribution guidance](https://learn.microsoft.com/partner-center/marketplace-offers/azure-partner-customer-usage-attribution#microsoft-marketplace-azure-apps).

The workflow state is written to:

```text
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\workflow-state.json
```

Each stage is explicitly started and completed so interrupted runs can resume
without relying on conversation history:

```powershell
sentinel-xdr-migration workflow-start-stage `
  --solution "Solutions\<solution>" `
  --stage discovery

sentinel-xdr-migration workflow-complete-stage `
  --solution "Solutions\<solution>" `
  --stage discovery `
  --status passed `
  --artifact inspection="Logs\sentinel-xdr-migration\<run-id>\inspection.json" `
  --evidence "Analytic Rules\Example.yaml"
```

Stages accept `passed`, `failed`, or `blocked`. Failed and blocked stages
require an explanation and can be retried after their cause is corrected.
Downstream stages remain locked until every dependency passes. The contract is
defined by [`schema/workflow-state.schema.json`](schema/workflow-state.schema.json).

Deployment, mock ingestion, and strict AR/CD alert parity are optional internal
qualification stages. They are not required for ISV authoring, PR submission,
Partner Center publishing, or customer deployment. To include them in an
approved non-production lab workflow, initialize with:

```powershell
sentinel-xdr-migration workflow-init `
  --solution "Solutions\<solution>" `
  --workflow-profile qualification `
  --tenant-id "<tenant-guid>" `
  --subscription-id "<subscription-guid>" `
  --workspace-resource-id "<workspace-arm-id>" `
  --workspace-customer-id "<workspace-customer-guid>" `
  --version-bump patch
```

Qualification writes a locked
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\qualification-target.json`. Live
commands load this context and reject any tenant, subscription, workspace ARM
ID, or workspace customer-ID mismatch.

Diagnose an unavailable exact ARM path without broad workspace discovery:

```powershell
sentinel-xdr-migration qualification-diagnose `
  --solution "Solutions\<solution>"
```

The diagnostic may perform one exact customer-ID lookup restricted to the
locked subscription. Apply its unique same-identity correction only after
explicit approval:

```powershell
sentinel-xdr-migration qualification-repair-target `
  --solution "Solutions\<solution>" `
  --approve-target-update
```

Inspect a solution:

```powershell
python -m sentinel_xdr_migration.cli inspect `
  --solution "Solutions\Azure Activity"
```

Convert every analytic rule:

```powershell
python -m sentinel_xdr_migration.cli convert `
  --solution "Solutions\Azure Activity"
```

Every conversion run automatically creates:

```text
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\transformation-report.html
```

The self-contained report shows attempted, converted, needs-review, and
conflict counts, followed by each rule's output status, warnings, and errors.
It can be opened locally without a server or external assets.

Validate the generated YAML:

```powershell
python -m sentinel_xdr_migration.cli validate `
  --solution "Solutions\Azure Activity"
```

Validate converted queries through Microsoft Graph Advanced Hunting:

```powershell
python -m sentinel_xdr_migration.cli validate-advanced-hunting `
  --solution "Solutions\Azure Activity"
```

The runtime validator probes required tables first. A query is reported as
`blocked` rather than `failed` when its Sentinel workload table is unavailable
in the current tenant. It creates:

```text
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\runtime-validation.graph.json
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\runtime-validation.graph.html
```

Agents using the official Triage MCP should inspect its advertised capabilities
and use suitable MCP tools first for all supported runtime query operations.
For Advanced Hunting, execute the queries from `validation-plan`, normalize the
results, and record them through the same reporting contract:

```powershell
sentinel-xdr-migration record-runtime-validation `
  --solution "Solutions\Azure Activity" `
  --provider triage-mcp `
  --results "<normalized-results.json>"
```

This creates `runtime-validation.triage-mcp.json` and
`runtime-validation.triage-mcp.html`. The public CLI does not implement or host
an MCP server; the repository skill invokes the configured official MCP.

For original Sentinel queries, the orchestrator falls back to Log Analytics
CLI/API when the connected MCP does not advertise a suitable workspace-query
tool or has a provider-level failure. Record those normalized results with
`--provider log-analytics-cli`; rules intentionally excluded from a targeted
live scenario can use the `not-run` status. For Advanced Hunting, the
orchestrator falls back to the Graph CLI. A genuine KQL error returned by
Triage is preserved as a failed detection and is not retried through another
provider.

## Strict live alert parity

Query execution alone does not prove migration parity. In a non-production lab,
the optional alert-parity workflow temporarily enables an already deployed
Sentinel Analytic Rule and its migrated Custom Detection, ingests a reviewed
payload containing a unique marker, and compares normalized alerts strictly.

For full internal qualification, create a JSON plan containing one contract,
payload, unique marker, and expected malicious key set per converted detection,
then enable all pairs and ingest all fixtures:

```powershell
sentinel-xdr-migration start-alert-parity-batch `
  --solution "Solutions\<solution>" `
  --plan "<qualification-plan.json>"
```

The plan must cover every converted detection. All rules must begin disabled
and are disabled again if any enablement or ingestion fails.

For targeted troubleshooting, start one or more explicitly selected rule
pairs with a shared fixture:

```powershell
sentinel-xdr-migration start-alert-parity `
  --solution "Solutions\<solution>" `
  --contract "<ingestion-contract>" `
  --payload "<mock-json>" `
  --scenario-marker "<unique-marker>" `
  --expected-match-key "<expected-malicious-key>" `
  --detection "<Detection.yaml>"
```

The command requires both rules to be disabled, enables them, invokes the
separate `azure-monitor-logs-ingestion` CLI, and emits provider-neutral capture
queries. It does not use fixed sleeps. Prefer official Sentinel Triage MCP
query tools and use the documented CLI/API fallbacks only for provider-level
failures.

After normalizing both alert sets, complete the comparison:

```powershell
sentinel-xdr-migration complete-alert-parity `
  --solution "Solutions\<solution>" `
  --results "<normalized-alert-results.json>"
```

Strict parity requires equal alert counts, stable match keys, severity, tactics,
entities, and decisive evidence. The observed keys must also equal the declared
malicious match-key set, so a benign false positive on both platforms still
fails. Completion disables every selected rule in a cleanup path even when
comparison fails. If capture cannot be completed, run:

```powershell
sentinel-xdr-migration abort-alert-parity --solution "Solutions\<solution>"
```

State and reports are written under
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>` as `alert-parity-state.json` and
`alert-parity-report.json`.

## Consolidated solution report

Build one solution-level JSON and HTML report after any stage:

```powershell
sentinel-xdr-migration solution-report `
  --solution "Solutions\<solution>" `
  --run-id "<run-id>" `
  --ingestion-report "<stream-one-ingestion-report.json>" `
  --ingestion-report "<stream-two-ingestion-report.json>"
```

The report includes every source rule, AR and CD identifiers and statuses,
conversion and structural results, runtime providers, deployment, strict alert
parity, entity recommendations, ingestion artifacts, and complete structured
errors. The HTML renders detailed errors in expandable sections; the JSON
retains the complete sanitized provider response rather than only a summary.

The offline HTML dashboard opens in **Needs attention**, with single-select
status chips, search by name/path/ID/finding, and multi-select issue categories.
Status, search, and category filters combine with AND; selected categories
combine with OR. Chip counts cover the full report. Shared-issue buttons reset
the other filters and show the affected rules. **Clear filters / show all**
restores the complete list.

Finding types are separate from readiness and have their own filter, affected-rule
counts, text/icon badges, shared-finding sections, and original-evidence sections:

- **Errors:** recorded hard errors or actual failed checks/executions.
- **Reviews:** explicit unresolved review reasons or recorded human-review flags.
- **Warnings:** nonblocking advisories, including source lookback/schedule warnings.
  These never become errors, human-review flags, or readiness failures merely
  because the UI displays them.
- **Blocked prerequisites:** recorded blocks, distinguished from execution failures.
- **Information:** explicit backend `informational` notes, such as a proven
  equivalent mapping or matched cadence/effective lookback. They are neutral,
  nonblocking context, never inferred by downgrading warning text. The selected
  manifest is authoritative (including an explicit empty list); only an absent
  field falls back to the draft's conversion provenance. JSON includes per-rule
  `informational`, total `summary.informational`, and `summary.rulesWithInformation`.
  Transformation HTML has a separate Information column; dashboard information
  has its own badge, filter, shared groups, and detail disclosure. Information alone
  never creates a review flag, failure, or Needs attention status.

Choosing a finding type resets the status filter to All, so the Warnings filter
also reveals advisories on ready rules. Search/categories still apply; status can
then be refined. Compact rows prioritize errors and reviews, with warnings in a
clearly labeled advisory disclosure. Counts deduplicate identical inherited
diagnostics per rule. A warning repeated verbatim as an explicit review reason
is counted once as a review, preserving both original records in its evidence;
unrelated warnings remain warnings. Types can overlap on the same rule.

The shared **Preserve source tactics; review historical single-tactic findings**
explanation labels older single-tactic findings as historical and recommends
explicit draft regeneration, not mandatory narrowing of authoring metadata.
Current verified Defender UI / Graph beta behavior (2026-10-07) uses one
tactic with multiple compatible techniques/subtechniques; the isolated beta
multi-tactic create request was rejected. The documentation's collection-shaped
`alertTemplate.tactics` property does not alone establish multi-tactic acceptance.
The explanation links the public Graph `alertTemplate` and `mitreTactic` references,
without including raw lab details or claiming ARM/future-version validation.

Affected rule details show the current Sentinel tactic and technique lists
independently, the original lists retained in conversion provenance, and the
exact current draft tactic/technique/subtechnique structure. Lists are never
paired by position. A first-original-tactic draft with no techniques is labeled
an unapproved fallback shape only when those recorded facts match. The report
provides a rule-ID-specific, placeholder-only `ruleOverrides` example for optional
technique corrections to one existing source tactic, without removing or
reordering other tactics. It never recommends a tactic from rule
names or silently applies an override, approves a mapping, edits KQL, or clears
review gates. Absent classification metadata remains explicitly unrecorded.

### Automated-check doughnut chart

The compact **High-level findings** pie appears near the top, separately from
the unique-rule doughnut. Its red slice counts distinct error findings, yellow
counts warnings plus review findings, and sky blue uses the theme link token for
informational findings. Findings are deduplicated within each rule using the
same evidence-preserving rules as the table; one rule can contribute multiple
findings. Blocked prerequisites are stated separately rather than counted as
errors or silently mixed into this pie.

A **green standalone rule metric**, not a slice, shows rules whose automated
conversion and structural checks passed with no actionable findings or per-rule
block; informational notes are allowed. It is not a deployment/semantic approval.
The pie legend and keyboard-accessible slices filter matching rules, so the
result-list count can differ from the slice's finding count. Selecting either
chart clears the other chart's selection; normal filters can then narrow it.

The self-contained SVG chart counts each rule exactly once, in this priority:
**red** actual errors; **yellow** warnings or explicit review decisions;
**green** converted plus passed local structural checks, with no warning/review
or per-rule prerequisite block (informational notes are allowed); **gray**
insufficient evidence or an otherwise unresolved per-rule prerequisite block.
Green is labeled **Automated checks passed**, not deployment approval. It is
independent of the run-level conversion review gate: a green rule may still have
the status **Readiness unconfirmed**. Historical semantic cautions stay at run
level, not fabricated per-rule flags. Legend buttons provide counts/percentages
and a text alternative; both segments and buttons support keyboard filtering.
Chart selection resets other filters, which can then narrow the chart group.
The existing status controls and rule badges remain available.

### Reviewed bulk tactic exports

The dashboard supports **pending review/export**, never automatic resolution.
Only historical explicit single-tactic review findings with unique source IDs, valid source
choices, and a recorded source-file SHA-256 are eligible. Select visible eligible
rules or individual rules, choose a source tactic to correct, then choose techniques
and confirm compatibility/observable behavior **individually for each rule**.
Incompatible source tactics are refused with a reason; applying a new bulk
tactic clears prior technique selections and confirmations. No compatibility
cross-product is invented. Rules needing a new tactic/technique absent from the
source lists, an empty technique selection, missing metadata, mapping redesign,
or timing/data-loss acceptance require individual review outside these controls.
There is no blanket `acceptedReviewReasons` export.
These legacy controls are optional technique corrections, not a requirement to
choose one tactic for authored YAML. Conversion retains all source tactics in
source order regardless of the selected override. Regeneration, rather than an
exported decision alone, refreshes historical conversion findings.

Import the existing **complete JSON configuration** to merge unrelated root
settings, rule overrides, and other fields within selected rule overrides.
Only selected `tactic` and `techniques` fields are replaced, with previous and
new choices shown in the preview. Alternatively, explicitly confirm there is no
existing configuration to preserve. JSON is valid YAML for the existing CLI.
For an existing YAML configuration, create a JSON equivalent locally first:

```powershell
python -c "import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding='utf-8-sig')), indent=2))" existing-config.yaml > existing-config.json
```

The browser never writes to the repository or calls a server. It downloads:

- `migration-reviewed-overrides.json`: the complete merged CLI configuration.
- `migration-reviewed-overrides.review.json`: a separate audit manifest containing
  selected source IDs, source file hashes, report/run identity, explicit choices,
  individual confirmations and prior selections; `applied` remains `false`.

Inspect both previews and compare source hashes against the current checkout;
re-import if the underlying configuration changed. **The CLI does not enforce
the review manifest or automatically reject stale decisions.** After explicit
review, apply the merged configuration through the existing tool:

```powershell
sentinel-xdr-migration convert --solution "<solution-path>" --run-id "<run-id>" --config "<downloaded-merged-config.json>" --overwrite
sentinel-xdr-migration solution-report --solution "<solution-path>" --run-id "<run-id>"
```

Do not pass the review manifest as `--config`. Conversion can replace
same-provenance drafts; inspect changes and continue the normal workflow gates.
Downloads do not change persisted findings/statuses or approve deployment.
Pending choices are browser-memory-only and are lost on refresh. Export is an
explicit user action; there is no local write server, external chart library,
automatic mapping choice, or external runtime dependency.

Optional browser regression tests use an already installed Playwright/browser:
set `SENTINEL_REPORT_BROWSER_TESTS=1`, optionally
`SENTINEL_REPORT_BROWSER_CHANNEL=chrome`, then run
`python -m unittest discover -s Tools/SentinelToXDRMigration/tests -p test_report_review_browser.py`.

### Run context and rule details

Run profile, stage states, workspace configuration presence, and recorded shared
messages appear once. A missing result is **evidence unavailable**, not proof of
a skipped check. **Not required** comes only from recorded workflow state.
Individual failures, blocked results, measured zero rows, and exceptions remain
visible even when a run-level stage is not required. Historical stage messages
are retained separately from current artifact counts.

**Ready for validation** requires a converted rule, passed local structural
checks, no recorded rule review flag/failure, and a recorded passed conversion
stage. This is not deployment approval or proof of semantic equivalence.
Automated successes remain **Readiness unconfirmed** while conversion review
is incomplete; unmapped semantic findings in workflow evidence are not silently
treated as resolved. These are presentation labels only: the dashboard never
changes gates, source statuses, or the existing JSON summary contract.

The compact rule list shows problems and next actions. Details retain warnings,
review reasons, entity recommendations, check results, and original diagnostics.
Identical inherited conversion/structural findings are grouped per rule, retaining
their stages and raw evidence; shared findings show affected-rule counts rather
than inflated occurrence totals. Categories are navigation aids, not semantic
validation. Source and converted KQL are captured from current files at report
generation and displayed with an offline unified text diff, not a claim of
query equivalence or a historical content snapshot. No external scripts, fonts,
services, or new dependencies are used. Theme follows the system preference or
`?scoutTheme=light` / `?scoutTheme=dark`.

Outputs:

```text
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\migration-report.json
Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\migration-report.html
```

## Deploy Custom Detections

Deployment uses the documented Microsoft Graph beta Custom Detection API. The
API is preview and requires delegated `CustomDetection.ReadWrite.All` consent
plus an appropriate Defender XDR or Entra security role.

Authenticate once:

```powershell
sentinel-xdr-migration setup-deployment `
  --solution "Solutions\<solution>" `
  --tenant-id "<tenant-id>"
```

This uses Azure CLI browser authentication by default. Device-code and direct
browser credential flows are also available:

```powershell
sentinel-xdr-migration setup-deployment `
  --solution "Solutions\<solution>" `
  --tenant-id "<tenant-id>" `
  --auth-method browser
```

Deploy every structurally valid, fully converted detection:

```powershell
sentinel-xdr-migration deploy --solution "Solutions\<solution>"
```

Rules are always submitted as disabled. The command creates missing rules,
updates matching client-provided IDs, and writes
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\deployment.graph.json`.

Use `--overwrite` to replace previously generated files. Without it, the
converter refuses to overwrite a file whose content differs.

## Optional migration configuration

Create `Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/migration-config.yaml` when a solution needs explicit
table, function, or column rewrites:

```yaml
schemaVersion: 1.0.0
tableMappings:
  LegacyTable_CL: CurrentTable_CL
functionMappings:
  LegacyParser: CurrentParser
columnMappings:
  LegacyTable_CL:
    UserName: AccountUpn
```

Mappings are applied token-by-token. Time-column handling is table-aware:
native Defender tables use `Timestamp`, while verified Sentinel workload
tables such as `AzureActivity` retain `TimeGenerated`. Rewrites skip quoted
strings and line comments. Runtime validation is authoritative for tables and
KQL constructs exposed through the unified Advanced Hunting surface.

Conversion does not require queries to mention or return `Timestamp` or
`TimeGenerated`, and does not add either column to satisfy a local check.
[Microsoft's custom detection guidance](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
recommends event-time columns for alert timing; when they are not projected,
alert first/last event times use the detection lookback window. This is not a
blanket conversion or structural-validation failure. Existing generated YAML
retains its recorded conversion errors until explicitly regenerated; historical
reports are not rewritten by this policy change.

Entity mappings are checked against columns plausibly produced by `project`,
`extend`, `summarize`, `distinct`, `parse`, and `mv-expand`. The analyzer
deliberately over-approximates output rather than blocking queries it cannot
prove invalid. High-confidence Account, Host, IP, URL, and Azure resource
columns can be repaired or inferred when source mappings are incomplete.

The generated file declares `resourceType:
Microsoft.Security/detectionRules`. A later packaging milestone can consume
this field and the `apiVersion`/`properties` block without reinterpreting the
source analytic rule.

## Agent skills

Repository-native skills under `.github/skills/` teach compatible agents how
to invoke this utility:

- `sentinel-xdr-end-to-end-orchestrator`
- `sentinel-xdr-rule-converter`
- `sentinel-xdr-detection-validator`
- `sentinel-xdr-migration-orchestrator`
- `sentinel-xdr-solution-packager`
- `sentinel-xdr-solution-deployer`
- `sentinel-xdr-alert-parity-validator`

The repository also provides one user-facing custom agent:

```text
.github/agents/sentinel-xdr-migration.agent.md
```

Select **Sentinel XDR Migration** from the host's agent picker. The agent uses
the top-level orchestrator skill, which delegates to the specialist skills
while the CLI remains the source of deterministic behavior and persisted
workflow state.

The skills call the CLI through the agent's normal terminal tools. They contain
no credentials and do not host a custom MCP server.

The canonical agent-neutral contract is:

```text
Tools\SentinelToXDRMigration\agent-workflows\end-to-end-migration.md
```

Thin adapters are provided for:

- generic agents through `AGENTS.md`;
- GitHub Copilot through `.github\agents` and `.github\skills`;
- Claude Code through `CLAUDE.md` and
  `.claude\skills\sentinel-xdr-migration\SKILL.md`;
- Cursor through `.cursor\rules\sentinel-xdr-migration.mdc`; and
- Windsurf through `.windsurf\rules\sentinel-xdr-migration.md`.

All adapters point to the same workflow and deterministic CLI. They must not
fork the stage definitions or make optional qualification mandatory.

Microsoft's official Sentinel Triage MCP can optionally provide Advanced
Hunting schema and execution tools:

`https://sentinel.microsoft.com/mcp/triage`

It is not required. The utility remains usable without MCP, and missing runtime
access never blocks offline conversion or structural validation.

## Logging

Runtime logs and reports are written below `Data/`:

- `Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/sentinel-xdr-migration.log`
- `Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/manifest.json`
- `Solutions/<solution>/Logs/sentinel-xdr-migration/<run-id>/runtime-validation.graph.json`

These files are local execution artifacts and are ignored by Git.

## Tests

```powershell
python -m unittest discover -s Tools\SentinelToXDRMigration\tests -p "test_*.py"
```

## Planned milestones

- workbook conversion;
- solution migration dashboard;
- optional retrieval-assisted guidance for schemas, prior art, and historical
  findings.
