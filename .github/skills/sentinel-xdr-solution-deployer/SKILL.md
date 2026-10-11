---
name: sentinel-xdr-solution-deployer
description: Deploy and verify Sentinel Analytic Rules and Defender XDR Custom Detections disabled in an approved non-production environment.
---

# Deploy Sentinel and XDR detections safely

Use this skill only after conversion, runtime validation, and packaging have
passed. Deployment is a write operation and always requires explicit user
approval for the exact subscription, resource group, workspace, solution, and
deployment mode.

## Modes

### One early scope-consent request

After the Qualification target is locked and before Discovery, review the
current local scope plan and ask once for consent to the bounded potential
action groups. Show the exact target, solution/version, inventory counts,
eligible IDs and caps, current package identity, resource types, and which
conditional prerequisites are proven, absent, or unknown. Include:

1. disabled Sentinel alert-rule and Graph Custom Detection creation or
   reviewed updates;
2. conditional fallback DCR/DCE creation;
3. conditional creation of a proven-absent custom-log table;
4. reviewed mock telemetry ingestion, including payload, records/batches,
   stream, estimated bytes/cost, and retention impact;
5. controlled alert parity, with exact pairs, proposed time window, bounded
   enable/restore operations, and abort restoration;
6. full-package installation and selected XDR Content Hub registration; and
7. explicitly owned cleanup/deletion, listing exact resources and ownership
   evidence while excluding pre-existing or unowned resources.

Use unselected structured choices: **Approve all currently bounded and
available components**, **Select components**, **Revise the plan**, or
**Decline advance consent**. “Approve all” is an explicit choice, never a
default. Ask again only if the target, plan identity, action/resource families,
payload, caps, package flags, or cleanup ownership changes. Missing or unknown
scope is provisional, not unlimited; denial does not block independent
read-only validation.

The current CLI can persist consent for the direct disabled AR/CD pair,
`fullPackageAcceptance`, `mockTelemetryIngestion`, `fallbackDcr`,
`fallbackDce`, and `customTableCreate`. `controlledAlertParity` is planning
metadata only until a finite test window and complete batch fixture plan are
bound; `ownedResourceCleanup` is unsupported because there is no exact
run-owned deletion inventory or deletion executor. Do not invent CLI
component names or represent either as consented. Previous narrow DCR/DCE
consent does not imply ingestion, parity enablement, package acceptance, or
cleanup consent.

Authentication, Entra admin consent, role assignments, and permission
readiness are separate from both advance planning consent and final resource
write approval. None implies another.

### Package acceptance

Validate and optionally deploy `Package\mainTemplate.json` as a complete
solution:

- `DeployAnalyticsRule=true` selects Sentinel Analytic Rule content.
- `DeployCustomDetection=true` selects both Defender XDR Custom Detection
  installation and Content Hub registration, independently of Sentinel content.
  Both selections may be true. Use only parameters declared by the package.

Use ARM validation or preview only when supported for the selected resource
types and deployment features. Bicep extensibility imports do not support
`what-if` ([Microsoft Learn: unsupported deployment
features](https://learn.microsoft.com/en-us/graph/templates/limitations#unsupported-deployment-features));
do not pass or wait for a `what-if` result for that route. An ordinary ARM
preview cannot prove extension acceptance, and ARM validation does not validate
extension behavior. Registration support remains unverified; emitted templates
are not proof of live acceptance. The obsolete `RegisterE5Content` and
`E5Flavor` controls are not declared. Exact-scope approval must explicitly
include registration when selecting CDs. Existing instances are not disabled or
removed by these switches.

Before the write step, review the latest local Qualification
`deploymentPlanning` scope and explicitly persisted component-specific
planning consent. If the bound plan is unchanged, do not repeat the broad
planning question. Planning consent is not write authority. Immediately before
each bounded write operation or batch, show its exact scope and obtain fresh
explicit approval. A single approval may cover the enumerated resource/API
operations in that batch; it need not be repeated for every HTTP request.
Require a new approval if any operation expands beyond the batch. Missing or
stale planning consent, permissions, or successful preflight does not
substitute for the immediate gate.

### Alert-parity preparation

Deploy both sides of every reviewed pair disabled:

```powershell
sentinel-xdr-migration deploy-analytic-rules `
  --solution "<solution-path>" `
  --workspace-resource-id "<workspace-arm-id>"

sentinel-xdr-migration deploy --solution "<solution-path>"
```

The first command writes
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\deployment.sentinel.json`. The
second writes
`Solutions\<solution>\Logs\sentinel-xdr-migration\<run-id>\deployment.graph.json`.

## Safety gates

Before any write:

1. Confirm the target is a non-production lab.
2. Show the subscription, resource group, workspace, tenant, solution, package
   version, mode, exact resource IDs, operation types, and count.
3. Immediately before the bounded operation/batch, require explicit approval
   for those exact values and the listed writes.
4. Confirm every Custom Detection YAML has `properties.status: disabled`.
5. Stop on unresolved conversion review, invalid KQL, missing entity mappings,
   duplicate IDs, or count mismatches.
6. Never infer permission from Entra Global Administrator. Verify Azure RBAC
   and Microsoft Graph Custom Detection scopes separately.
7. Ask before launching interactive authentication.

## Verification

Deployment passes only when:

- every requested ARM or Graph operation succeeds;
- deployed AR and CD IDs match the reviewed source manifest;
- every deployed rule is disabled;
- display names, queries, schedules, severities, tactics, and entity mappings
  match the generated artifacts; and
- the deployment reports contain no failed or silently skipped item.

If Graph read permission is unavailable, report verification as blocked even
when the write deployment reports success. Do not claim live status solely
from the source template.

Do not enable a rule in this skill. Rule enablement belongs exclusively to
`sentinel-xdr-alert-parity-validator`, which must disable every test rule on
completion or abort.
