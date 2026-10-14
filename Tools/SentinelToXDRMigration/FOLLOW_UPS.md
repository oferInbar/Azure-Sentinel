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
- **Map eligible Sentinel `kind: NRT` rules to Continuous (`NRT`) Custom Detections.**
  Mapped eligible single-table `kind: NRT` rules to `kind: CustomDetection`
  with `schedule.frequency: "NRT"`, surfacing incompatible multi-table, join,
  union, or aggregate NRT queries for explicit review.
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

## Candidate follow-ups

- **Reconcile Qualification readiness.** Review existing authorization and
  access checks, then separately assess deployment and ingestion permission
  readiness before proposing new implementation.
- **Review private configuration and support exports.** Reconcile existing
  target-configuration and support-export handling before making claims about
  exposure or adding controls.
- **Improve operator visibility.** Consider concise progress and preflight
  reporting, a workflow diagram, watchdog summaries, and suppression of
  no-change notices.
- **Add scheduled migration status reminders.** Consider a scheduled agent
  that reminds the top coordinator to surface what is being worked on, what
  comes next, and why a step is taking longer, including larger detection
  batches. For example: "Applying your decisions to the XDR detections before
  validation." Bind updates to actual workflow and subagent evidence; never
  invent progress, completion estimates, or approvals. Coordinate with the
  existing single-owner watchdog, avoid repetitive notices, and do not create
  a second workflow executor. Review the cadence and design separately before
  implementing an agent or enabling a schedule.
- **Forward explicit approval safely.** Route chat approval to the accountable
  owner while preserving the exact approved operation, scope, and bindings.
- **Clarify execution ownership.** Use appropriate delegation with one owner
  and no duplicate executors for the same operation.
- **Change the validation tools to verify ARM templates through lab deployment.**
  Make deployment of the generated `mainTemplate` to an explicitly approved
  non-production lab the default ARM validation route for both Authoring and
  Qualification, skipping ARM-TTK on that route and using deployment results
  to verify ARM template deployment validity. Allow Authoring to select
  ARM-TTK instead of lab deployment verification. Save deployment findings,
  including failures and target/artifact bindings, as workflow evidence.
  Ask in advance during preflight for preapproval to deploy the solution ARM
  templates to the selected lab, stating the expected content items:
  X Sentinel rules, Y workbooks, and Z custom detections.
  Deployment verification alone does not establish functional/runtime
  qualification or alert parity.

Any future environment write remains separately gated by explicit approval
immediately before the exact operation. No cloud action is authorized by this
roadmap.
