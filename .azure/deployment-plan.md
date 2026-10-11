# Endpoint option 1 feasibility deployment

## Status
Deployed: ARM Succeeded; independent Defender XDR existence/disabled-state readback pending

## 1. Objective
Test direct root-level MicrosoftSecurity XDR detections alongside Sentinel content.
Do not modify the release template, ZIPs, or the user's existing changes.

## 2. Recipe
- recipe.type: azcli
- Existing ARM JSON; no AZD, compilation, infrastructure scaffolding, or new workspace.
- Template: Solutions/Endpoint Threat Protection Essentials/Package/mainTemplate.option1.json

## 3. Approved Azure context
- Tenant: 9ad27f02-5ed8-490a-8113-8ff847030e0a
- Subscription: a718424a-41c0-432d-a17b-38af96331f5c
- Resource group: ContentCreation
- Workspace: ContentTestCreation
- Workspace customer ID: 906212d4-cf6f-4086-ac72-e884b1b41850
- Region: eastus
- Parameters: workspace=ContentTestCreation, workspace-location=eastus, location=eastus, E5Flavor=true
- Deployment mode: Incremental

## 4. Scope and safety
Expected active resources: one content package, 15 hunting content templates,
and 15 disabled XDR detections. Analytic templates are conditionally skipped.
No attribution marker or nested deployment resources.
Existing matching resource/detection IDs may be updated; XDR resources may be
tenant-scoped rather than isolated to this workspace.
User approved validation followed by deployment on 2026-10-06, with a local
deployment plan that must not be committed.
After receiving the failed what-if results and the documented extensibility
limitation, the user explicitly selected: "Deploy now, accepting the what-if
limitation and possible partial deployment". This authorizes an actual
Incremental deployment with E5Flavor=true despite the unavailable XDR preview.
Re-run ARM Provider validation before execution; do not claim what-if passed.
No permission changes, provider registrations, rule enabling, or cleanup
deletions are authorized.

## 5. Preparation
- Source template generated and structurally checked in the previous turn.
- Tenant inventory confirmed subscription, resource group and Sentinel workspace.
- Reconfirmed subscription tenant, Enabled state, exact workspace customer ID,
  eastus location and workspace Succeeded state through ARM.
- Azure CLI subscription cache does not contain the target subscription.
  Tenant-scoped token acquisition and ARM access both succeed. Use the equivalent
  ARM deployment REST API without changing the shared CLI subscription context.
- ARM Provider-level validation returned Succeeded.
- What-if failed for all 15 XDR declarations. The existing nested template
  fails the same way; the option-1 template with E5Flavor=false succeeds.

## 6. Execution
Acquire tokens through the repository az-cli-command-runner wrapper.
Use explicitly scoped ARM REST URLs; do not change the default subscription.
Stop on authentication, authorization, template or extension validation failures.
After success, deploy the exact validated template and verify deployment state
and resource operations. Do not enable detections or delete resources.

Pre-deploy checklist completed through `azure-deploy`:
- Approved subscription/tenant, existing RG/workspace and eastus are explicit,
  not inferred from the shared default CLI account.
- ARM JSON/non-AZD recipe applies. No scaffolding, AZD environment, app build,
  SQL migrations, containers, or managed-identity/RBAC changes are applicable.
- Fresh Provider validation proof and exact hash recorded in section 7.
- Use one unique deployment PUT and a persistent intent marker; never retry an
  uncertain submission. Recover and poll by GET only, up to 15 minutes.
- Snapshot Sentinel content before/after, fetch all operation pages, inspect
  imported-resource targets without filtering them out, preserve partial state.
- ARM create/update, GET and operation-list definitions verified against
  Microsoft Learn REST API `2025-04-01` reference pages.

## 7. Validation Proof
Deployment validation gate (explicit exception; not all preview checks passed):
- [x] Azure CLI installed and tenant-scoped authentication succeeds.
- [x] Target subscription and workspace identity verified through ARM GET.
- [x] ARM JSON structural checks (no Bicep build or Docker build applicable).
- [x] Provider-level ARM validation returned Succeeded; this does not establish
  successful XDR creation or complete extension permission coverage.
- [ ] What-if preview: failed and not rerun; user explicitly waived this preview
  gate for the unchanged feasibility deployment. This is NOT a passed what-if.
- [x] Bicep compilation / Docker build: not applicable to existing ARM JSON.
- [x] Provider validation reports no policy rejection. Separate policy inventory
  and Defender workload permission/licensing verification are not established.
- [x] Static role verification: no new identities or role assignments declared.

CLI subscription-specific commands fail because the subscription is absent from
the local account cache; ARM GET succeeds using the target tenant token.
Validation and deployment use the equivalent REST endpoints instead.

Actual checks on 2026-10-06:
- POST deployments/endpoint-option1-20261006T100015Z/validate?api-version=2025-04-01
  with validationLevel=Provider, E5Flavor=true: HTTP 200, Succeeded.
- POST the same deployment's whatIf endpoint: Failed, InvalidTemplateDeployment,
  with 15 ProviderError details targeting xdrDetection01 through xdrDetection15.
- `python3 <session>/files/option1_preflight.py 'Solutions/Endpoint Threat Protection Essentials/Package/mainTemplate.json' option1-baseline-nested-xdr --e5 true`
  failed with the same 15 internal ProviderError results inside the nested templates.
- `python3 <session>/files/option1_preflight.py 'Solutions/Endpoint Threat Protection Essentials/Package/mainTemplate.option1.json' option1-without-xdr --e5 false`
  succeeded.
- Validated template SHA256:
  8f9bb876a17253dcbcb1394ff5ad0255d39987cb3062d1c573f826d780155999

Fresh approved-deployment validation (2026-10-06T10:13:14.747Z):
- Invoked `azure-validate`, `az-cli-command-runner`, and `microsoft-code-reference`.
- Command: `python3 ../../../.copilot/session-state/88ca3b4c-8383-4b8c-99de-2b9e943c5d00/files/option1_approved_deployment.py validate`.
- Equivalent request: `POST https://management.azure.com/subscriptions/a718424a-41c0-432d-a17b-38af96331f5c/resourcegroups/ContentCreation/providers/Microsoft.Resources/deployments/endpoint-option1-live-20261006T101306Z/validate?api-version=2025-04-01`.
- Request properties: `mode=Incremental`, `validationLevel=Provider`,
  exact template with SHA256 above, and the four parameters in section 3.
- Result: HTTP 200, `properties.provisioningState=Succeeded`, no error.
- Fresh subscription GET: Enabled, approved tenant and subscription confirmed.
  Fresh workspace GET: exact resource ID/customer ID, eastus, Succeeded.
- JSON structure verified: 46 allowed resource declarations, 15 XDR statuses
  Disabled, root solutionPackage dependency, no role assignments/identities.
- Full credential-free responses saved in the session `files/` directory as
  `endpoint-option1-live-20261006T101306Z-validation.json` and
  `endpoint-option1-live-20261006T101306Z-preflight-{subscription,workspace}.json`.
- Manifest: `option1-approved-deployment-manifest.json`. No shared CLI context
  change. Credentials stayed in process memory.
- Deployment proceeds under the explicit what-if exception in section 4, not
  under any claim that the failed preview passed or proved XDR feasibility.

Root-XDR what-if diagnostic:
- Timestamp: 20261006T100102Z
- Tracking ID: 2fe5e88e-d499-4387-9c70-aa284bf9bc97
- Request correlation ID: 071a60d4-06f6-40f6-b017-4925e8607d8e

Evidence is saved in the session files as option1-arm-validation.json,
option1-arm-whatif.json, option1-baseline-nested-xdr.json and
option1-without-xdr.json. The shared XDR provider/preflight failure does not
establish that root-level resource promotion is invalid, nor does successful
ARM validation prove actual XDR deployment or Marketplace acceptance.

Parallel investigation findings:
- Microsoft documents what-if as unsupported for "Bicep extensible resources,
  including Microsoft Graph resources":
  https://learn.microsoft.com/en-us/graph/templates/bicep/limitations#unsupported-deployment-features
  This supports an extension what-if limitation, but no MicrosoftSecurity-specific
  documentation was found mapping this exact ProviderError to that limitation.
- The Sentinel custom-detections guide documents root-level MicrosoftSecurity
  declarations and direct deployment. OCI package tag v1.0.1 and ARM import
  version 1.0.0 are different version mechanisms; no mismatch has been proven.
- Four read-only ARM GETs completed at 2026-10-06T10:06:54Z:
  Microsoft.SecurityInsights is Registered; Microsoft.Security is NotRegistered
  and does not advertise detection resource types; RG caller permissions include
  actions ["*"] with no exclusions in that entry; workspace product settings
  list EyesOn, IPSyncer and Anomalies as enabled.
- Microsoft.Security registration is not equivalent to MicrosoftSecurity
  extensibility-provider readiness. No registration or RBAC change was attempted.
- Defender onboarding, licensing, custom-detection workload authorization and
  extension-backend availability remain unverified by the available ARM reads.
- No evidence-based template-only fix was identified. The actual deployment
  below succeeded under the explicit preview exception; provider clarification
  of what-if behavior is still useful but was not an execution blocker.

## 8. Deployment Results
### Actual execution
- Invoked `azure-deploy` after fresh successful Provider validation.
- Command: `python3 ../../../.copilot/session-state/88ca3b4c-8383-4b8c-99de-2b9e943c5d00/files/option1_approved_deployment.py deploy`.
- Deployment name: `endpoint-option1-live-20261006T101306Z`.
- Resource ID:
  `/subscriptions/a718424a-41c0-432d-a17b-38af96331f5c/resourcegroups/ContentCreation/providers/Microsoft.Resources/deployments/endpoint-option1-live-20261006T101306Z`.
- [Azure portal deployment](https://portal.azure.com/#@9ad27f02-5ed8-490a-8113-8ff847030e0a/resource/subscriptions/a718424a-41c0-432d-a17b-38af96331f5c/resourcegroups/ContentCreation/providers/Microsoft.Resources/deployments/endpoint-option1-live-20261006T101306Z/overview).
- Exactly one `PUT https://management.azure.com{resource ID}?api-version=2025-04-01`,
  with `properties={mode:"Incremental", template:<exact validated JSON>,
  parameters:<section 3 values>}`. No resubmission or corrective deployment.
- PUT response at 2026-10-06T10:14:20.850Z: HTTP 201, Accepted.
  Acceptance was not treated as deployment success.
- Polled deployment GET until **Succeeded**, confirmed at
  **2026-10-06T10:15:10.461Z**. No terminal error.
- Deployment correlation ID: `fd1d7250-e06e-4527-b751-99b4df9a39d2`.
- Exact template SHA256 remained
  `8f9bb876a17253dcbcb1394ff5ad0255d39987cb3062d1c573f826d780155999`.
- Tenant/subscription/workspace identity was rechecked immediately before PUT;
  the unique deployment name did not exist (HTTP 404) before submission.

### Resource outcomes and verification

| Resource type | Succeeded | Failed | Skipped | New vs existing |
| --- | ---: | ---: | ---: | --- |
| Sentinel content package | 1 | 0 | 0 | 1 new; no prior package in workspace |
| Sentinel hunting content templates | 15 | 0 | 0 | 15 new; no prior content templates in workspace |
| MicrosoftSecurity XDR custom detections | 15 | 0 | 0 | Unknown; stable IDs can create or update tenant rules |
| Sentinel analytic content templates | 0 | 0 | 15 | Condition false with E5Flavor=true; not submitted |

- The operations endpoint returned 32 records with no nextLink: 31 successful
  resource Create operations (`statusCode=OK`) and one successful
  EvaluateDeploymentOutput operation. No failed or canceled operations.
- All XDR operations were explicitly retained and checked using
  `targetResource.extension`, `symbolicName`, and `identifiers.id`, rather than
  filtering for ARM resource IDs. `xdrDetection01` through `xdrDetection15` each
  report Succeeded/OK under MicrosoftSecurity version 1.0.0, and each stable
  identifier matches the exact template. All submitted statuses were `disabled`.
- Before/after Sentinel list GETs independently show the new
  `azuresentinel.azure-sentinel-solution-endpointthreat` package, version 3.0.8,
  and all 15 expected HuntingQuery content templates. Their IDs match all 16
  deployment outputResources. No previously existing Sentinel package/template
  was touched according to this inventory.
- Command: `python3 ../../../.copilot/session-state/88ca3b4c-8383-4b8c-99de-2b9e943c5d00/files/option1_approved_deployment.py verify`.
  Passed all 31-operation, symbolic-name, identifier, count, content-kind,
  before/after inventory, outputResources and template-hash assertions at
  2026-10-06T10:18:48.995Z.
- Live role verification: not applicable to new app identities or role
  assignments; none were declared or created. No permission changes attempted.

### Remaining verification boundary
- Actual ARM execution of the root-level option-1 template is proven successful,
  including successful provider-reported outcomes for all 15 XDR resources.
- Independent Defender rule existence and persisted disabled status are **not**
  confirmed: deployment GET lists only the 16 Sentinel outputResources, and XDR
  operation records do not return live rule properties.
- No documented ARM extension-resource property read endpoint was identified in
  the official 2025-04-01 or 2026-06-01 deployment specifications. No guessed
  mutation, extra deployment, or permission change was used for readback.
- The documented Sentinel custom-detection deployment verification recommends
  checking the Defender portal. This remains a follow-up; do not enable rules
  to perform it. XDR created-versus-updated distinction is also unknown.
- Full end-to-end XDR feasibility, actual query execution, licensing coverage,
  and Marketplace acceptance are **not** claimed. What-if is still recorded as
  failed with the user-approved exception, never as passed.
- Todo `xdr-deployment-resolution` remains blocked only on independent XDR
  existence/disabled-state readback; the actual deployment itself succeeded.

### Persistent evidence and preservation
All full responses and the helper are in session
`88ca3b4c-8383-4b8c-99de-2b9e943c5d00/files/`:
- `option1_approved_deployment.py`
- `option1-approved-deployment-manifest.json`
- `endpoint-option1-live-20261006T101306Z-validation.json`
- `endpoint-option1-live-20261006T101306Z-put-intent.json`
- `endpoint-option1-live-20261006T101306Z-submission.json`
- `endpoint-option1-live-20261006T101306Z-monitor-20261006T101420Z-get-003.json`
- `endpoint-option1-live-20261006T101306Z-monitor-20261006T101420Z-operations-000.json`
- `endpoint-option1-live-20261006T101306Z-monitor-20261006T101420Z-summary.json`
- `endpoint-option1-live-20261006T101306Z-verified-outcomes.json`
- The same deployment prefix includes credential-free identity checks, absence
  check, earlier GET polls, and before/after package/template inventories.

Only this local deployment plan was edited in the repository by this execution.
Existing source/template/ZIP/release-note changes were preserved; no queries,
release files, or the validated option-1 template were edited. No detections
were enabled, resources deleted, providers registered, permissions assigned,
default CLI subscription changed, or commits/pushes made.
