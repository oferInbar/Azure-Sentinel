# Create Solution V3.1

`createSolutionV3_1.ps1` supports both local and GitHub pipeline invocation.
Both entry points live in the V3 directory:

- `V3\createSolutionV3.ps1` remains the legacy Sentinel-only local entry point.
- `V3\createSolutionV3_1.ps1` adds XDR Detection packaging, supports local use,
  and remains the CI entry point.

Both entry points use `common\commonFunctions.ps1` for the core packaging
implementation. Only V3.1 enables Defender XDR Custom Detection injection.

They are alternative entry points, not two required packaging steps. Use V3
for a legacy Sentinel-only package and V3.1 when the solution contains XDR
Detections. The repository pipeline runs V3.1 for PR/CI packaging.
The former `V4/createSolutionV4.ps1` entry point was renamed, not the legacy
`pipeline/createSolutionV4.ps1`. Package-version selection and
`contentSchemaVersion` are unchanged; the V3.1-only release-version guards below
reject out-of-range selections.

## Local usage

```powershell
.\Tools\Create-Azure-Sentinel-Solution\V3\createSolutionV3_1.ps1 `
  -SolutionDataFolderPath ".\Solutions\<solution>\Data" `
  -VersionMode local `
  -VersionBump none
```

The local parameter set calls `common\createSolutionLocal.ps1` directly. V3
uses the same common implementation through its own adapter; neither entry
point invokes the other.

Use `none` for repeat validation without changing source versions. Use
`patch`, `minor`, or `major` when preparing a release; those options persist
the new version into the solution data file and `SolutionMetadata.json`.

## Pipeline usage

In CI, V3.1 receives pipeline-calculated metadata and version parameters. The
package automation calls it through:

```text
.script\package-automation\package-generator.ps1
```

The positional pipeline parameter contract is unchanged.

## Release-version bounds (V3.1 only)

V3.1 applies these hard guards in local, catalog, and positional pipeline modes:

| Release version | Accepted range |
|---|---|
| Effective solution/package version, even without XDR content | `>= 3.1.0` and `< 4.0.0` |
| Effective XDR Custom Detection content version | `>= 3.1.0` and `< 4.0.0` |
| Every other packaged content-item release version | `< 4.0.0`; existing `1.x`/`2.x` versions remain valid |

The guard reports the content type/path, effective version, and required range.
It never promotes versions automatically. Explicit local bumps are evaluated
before output: for example, `major` from `3.1.0` selects `4.0.0` and is rejected.
All version checks run before generated JSON/ZIP files are overwritten. Local
bump persistence is deferred until version validation and package generation
succeed; rejected versions leave the source versions and existing outputs intact.
Pipeline Data `Version` and calculated package version must agree exactly.
The existing missing-solution-version default (`3.0.0`) is below the minimum and
is rejected; supply an appropriate version explicitly.

Checks reuse each generator's effective version rather than scanning arbitrary
`version` fields: analytic/hunting YAML version (default `1.0.0`); parser
`Function.Version` (default `1.0.0`); workbook metadata version; playbook
`hidden-SentinelTemplateVersion` (default `1.0`, also the effective default for
packaged custom APIs/function apps); connector UI metadata version (default
`1.0.0` only when metadata is absent); summary-rule version; watchlist solution
version; and CCF `DataConnectorCCFVersion` (fallback solution version), shared by
connector-definition and connections content. Missing/invalid effective versions
without an existing generator default fail rather than gaining a new default.
Non-XDR numeric release versions support existing two-to-four-component
representations; comparison does not rewrite the emitted value.

**Independent XDR version:** every XDR YAML must declare its own top-level
`version` as a `major.minor.patch` string in `[3.1.0, 4.0.0)`. New conversions
start at `3.1.0`, independently of Sentinel source versions such as `1.0.2`.
Regeneration preserves valid existing XDR versions for the same source rule;
it does not reset `3.1.1` or silently replace an invalid `4.0.0`.
`contentProvenance.source.version` remains the original Sentinel release.
The packager uses the XDR version for registration metadata and content product
IDs, and checks it even when `Include XDR Content Registration` is false.
Data `XDR Detection Version`, solution version, and source provenance are not
fallbacks in V3.1. Missing or invalid XDR versions fail before package output.
For older files with no top-level version, review manual edits and explicitly
reconvert with `--overwrite` to initialize `3.1.0`, or author the independent
version. Never falsify provenance. A solution bump does not bump XDR versions.

These guards do not govern ARM `apiVersion`, `contentSchemaVersion`, ARM template
`contentVersion`, extension-provider versions, converter/schema versions, or
saved-search API revision numbers. Legacy `V3/createSolutionV3.ps1` and
`pipeline/createSolutionV4.ps1` retain their previous version behavior.

## Optional customer usage attribution

Set optional `trackingId` in the solution's **SolutionMetadata.json** to the
**complete customer usage attribution tracking ID** copied from Partner Center
**offer > plan > Technical configuration**, for example:

```json
"trackingId": "pid-399fb80b-c914-4257-b61e-91ab73733888-partnercenter"
```

This example is illustrative; do not copy it into an offer. Never synthesize an
ID, use a bare GUID, or substitute a Partner ID or plan ID. The packager accepts
full `pid-` identifiers, including non-GUID identifiers, validates literal ARM
deployment-name characters and the 64-character limit, and uses the supplied
string unchanged. This syntax check does not verify ownership or registration.

Local and pipeline packaging read this value from SolutionMetadata.json even
when the Data input already contains consolidated metadata. It is a
packaging-only setting, not a SecurityInsights RP metadata property.

When supplied, V3.1 adds exactly one root `Microsoft.Resources/deployments`
marker (API `2025-04-01`, mode `Incremental`) containing an empty template with
schema `https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#`,
contentVersion `1.0.0.0`, and `resources: []`. The root remains an implicit ARM
language-version-1 template with a resources array; functional XDR deployments
retain their nested language-version-2 templates. The marker is added after
metadata resource filtering and is included in mainTemplate.json and the ZIP.

If `trackingId` is absent, null, or blank, packaging continues without a marker.
For nested XDR packages it emits a prominent warning: Partner Center cannot
automatically add tracking when deployments are used for functional purposes.
Obtain the ID, add `trackingId`, and rebuild. This is a **missing attribution**
warning, not a claim that Marketplace will necessarily reject the upload.
See [Microsoft Marketplace Azure apps customer usage attribution](https://learn.microsoft.com/partner-center/marketplace-offers/azure-partner-customer-usage-attribution#microsoft-marketplace-azure-apps).

The migration CLI uses `package-v3-1` and writes `packaging.v3_1.json` with
`packager: V3.1`. Old V4 reports are historical evidence, not V3.1 evidence:
rebuild rather than rename or edit old reports.

## Focused regression checks

From the repository root (Python 3.11/3.12, PowerShell 7, and `powershell-yaml`):

```bash
PYTHONPATH=Tools/SentinelToXDRMigration:Tools/SentinelToXDRMigration/tests python -m unittest test_packaging test_workflow test_customer_usage_attribution test_version_policy test_converter
```

The attribution tests exercise both local and positional pipeline entry points
with isolated synthetic solutions, verify generated JSON and ZIP contents, and
cover missing/invalid IDs and nested XDR preservation. They stub the unrelated
full repository validators and isolate repository-root resolution. They do not
build existing solution packages, deploy to Azure, or prove Marketplace upload
acceptance. Version tests also cover boundaries, catalog-result guards, effective
defaults, local bumps, pipeline consistency, and rejection without source/output
mutation.
Converter tests cover independent XDR initialization, unchanged source provenance,
version preservation, explicit legacy reconversion, and invalid-version conflicts.

## Local parser names in Custom Detections

Before emitting CD installation and registration bodies, the shared packager renames
local KQL bindings that match the solution's parser names or aliases. Both bodies receive
the same query. Source YAML and native parsers are not edited. This also protects inputs
that were authored outside the migration converter.

For solutions with parsers, install Node.js and run
`npm ci --prefix Tools\SentinelToXDRMigration\kql` from the repository root.
The shared Microsoft KQL semantic helper preserves binding scope and rejects unsafe
rewrites rather than falling back to text replacement. See the migration-tool README's
"Local parser bindings" section for limits and regression commands.
