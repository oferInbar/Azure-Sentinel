---
name: sentinel-xdr-solution-packager
description: Package a complete Microsoft Sentinel and Defender XDR solution through the V3.1 packaging implementation.
---

# Package a Sentinel and Defender XDR solution

Use this skill after solution content and any `XDR Detections/*.yaml` files are
complete and structurally validated.

The XDR Solution Manager workflow always runs V3.1. Legacy V3 remains available outside
this workflow for legacy Sentinel-only packaging and intentionally ignores XDR
Detections. Never use V3 to satisfy this workflow's packaging stage.

The generated package remains a full Microsoft Sentinel solution. When XDR
Detections are declared, it also supports hybrid installation:

- `E5Flavor=false` installs Sentinel Analytic Rules.
- `E5Flavor=true` installs their matched Defender XDR Custom Detections.
- Custom Detections are always packaged disabled.

## Scope

This skill:

- validates the solution-data packaging contract;
- selects and applies one semantic version increment;
- runs the supported local packaging entry point;
- verifies the generated template, parameter file, and ZIP;
- checks AR-to-CD matching and hybrid deployment conditions; and
- reports validation failures without hiding or weakening them.

It does not convert Analytic Rules, create mock data, deploy the generated
template, enable detections, or validate alert parity.

## Inputs

- A solution folder under `Solutions\`.
- The solution data folder, normally `Solutions\<solution>\Data`.
- The version action: `none`, `patch`, `minor`, or `major`.

Use `none` for repeat local validation. Before producing a package intended for
submission, ask which release increment to apply. Never bump the version more
than once for the same package attempt.

V3.1 requires effective solution and XDR content release versions in
`[3.1.0, 4.0.0)`. Other content release versions must be below `4.0.0`; their
legacy lower versions remain valid. Out-of-range versions are hard errors, not
automatic promotions. A major bump from `3.x` is therefore rejected.
XDR currently takes `contentProvenance.source.version`, falling back to Data
`XDR Detection Version`, then solution version. This check applies even without
XDR registration. Do not falsify source provenance or invent an independent
CD-version field to satisfy it; surface that authoring limitation.
These bounds do not apply to API, schema, or extension-provider versions.

## XDR packaging contract

When the solution contains Custom Detections, confirm its solution-data JSON
contains:

```json
{
  "Analytic Rules": [],
  "XDR Detections": [],
  "XDR Detection Version": "1.0.0",
  "Include XDR Content Registration": false
}
```

For every XDR Detection YAML, require:

- `kind: CustomDetection`;
- `resourceType: Microsoft.Security/detectionRules`;
- a supported `apiVersion`;
- a stable `properties.id`;
- `contentProvenance.source.id` matching exactly one packaged Analytic Rule;
- a query, schedule, alert template, and reviewed entity mappings; and
- `properties.status: disabled`.

Do not enable `Include XDR Content Registration` unless the user explicitly
requests it and the live resource provider is known to support registration.

## Workflow

1. Work from the repository root.
2. Confirm PowerShell 7.1 or newer, Node.js, and the `powershell-yaml` module are
   available. Install missing dependencies only after confirming they are
   required.
3. Inspect the solution-data JSON and all referenced files. Stop on missing,
   duplicate, conflicting, or review-required content.
4. Verify every `contentProvenance.source.id` resolves to exactly one Analytic
   Rule content ID.
5. Confirm the current solution version and the requested bump. Check that
   `ReleaseNotes.md`, when present, can be synchronized to the resulting
   version.
6. Run the deterministic toolkit wrapper:

   ```powershell
   sentinel-xdr-migration package-v3-1 `
     --solution ".\Solutions\<solution>" `
     --version-bump none
   ```

   Use `none` for validation without modifying source versions. Replace it with
   the approved `patch`, `minor`, or `major` value when producing a release
   package; those options update the solution data and metadata versions. The
   wrapper invokes
   `Tools\Create-Azure-Sentinel-Solution\V3\createSolutionV3_1.ps1` with local
   version mode, validates every required output and the ZIP, and writes
   `Reports\<solution>\sentinel-xdr-migration\packaging.v3_1.json`.

   Never reuse pre-existing package artifacts as proof that this stage ran.
   Complete the workflow stage only with the wrapper's `workflowArtifacts`
   values, including `packager=V3.1` and `packageReport`.
   Historical V4 reports are not V3.1 evidence; rebuild rather than relabel them.

   Optional `trackingId` in SolutionMetadata.json must contain the complete ID
   copied unchanged from Partner Center > offer > plan > Technical configuration.
   Never synthesize it or substitute a bare GUID, Partner ID, or plan ID.
   If absent or blank, packaging continues without a marker and nested XDR
   packages warn that Partner Center cannot auto-add attribution for functional
   nested deployments. Surface that warning and recommend adding the ID and
   rebuilding; do not claim upload rejection.
   See [official attribution guidance](https://learn.microsoft.com/partner-center/marketplace-offers/azure-partner-customer-usage-attribution#microsoft-marketplace-azure-apps).

7. Require successful packaging and inspect:

   - `Package\mainTemplate.json`;
   - `Package\createUiDefinition.json`;
   - `Package\testParameters.json`; and
   - `Package\<version>.zip`.

8. For a hybrid package, verify:

   - `E5Flavor` exists and defaults to `false`;
   - every matched AR has condition
     `[not(parameters('E5Flavor'))]`;
   - every CD nested deployment has condition
     `[parameters('E5Flavor')]`;
   - AR, CD deployment, and CD ID counts match;
   - every CD body has `status: disabled`;
   - deployment names and CD IDs are unique and deterministic;
   - Content Hub registration is absent unless explicitly enabled; and
   - the generated ZIP version matches the solution-data version.

9. Run the repository packaging validations. Do not classify skipped tests as
   passed. Separate genuine template failures from documented validator or
   environment limitations.
10. Report the generated version, artifact paths, content counts, validation
    results, and any deployment prerequisites or unresolved failures.

Packaging is complete only when the artifacts exist, versions are synchronized,
all expected resources are present, the V3.1 evidence report is accepted by the
workflow gate, and no unexplained validation failure remains.
