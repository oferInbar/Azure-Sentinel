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

### Package acceptance

Validate and optionally deploy `Package\mainTemplate.json` as a complete
solution:

- `DeployAnalyticsRule=true` selects Sentinel Analytic Rule content.
- `DeployCustomDetection=true` selects both Defender XDR Custom Detection
  installation and Content Hub registration, independently of Sentinel content.
  Both selections may be true. Use only parameters declared by the package.

Run an Azure Resource Manager validation or what-if before create. Registration
support remains unverified; do not treat emitted templates as proof of live
acceptance. The obsolete `RegisterE5Content` and `E5Flavor` controls are not
declared. Exact-scope approval must explicitly include registration when
selecting CDs. Existing instances are not disabled or removed by these switches.

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
   version, mode, and expected rule count.
3. Require explicit approval for those exact values.
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
