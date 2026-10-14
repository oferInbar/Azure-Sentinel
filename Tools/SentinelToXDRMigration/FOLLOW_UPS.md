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

## Candidate follow-ups

- **Make workbook depends on parsers during packaging.** Approved toolkit
  implementation work: bind reviewed workbook function prerequisites to actual
  `Microsoft.OperationalInsights/workspaces/savedSearches` resources in the
  same enclosing ARM template and add workbook-installer `dependsOn` edges.
  Required parser installation is mandatory; same-resource parser overwrites
  are expected. Keep this tracked until packaging regressions confirm exact
  resource mapping, prerequisite freshness, and unconditional installation.
- **Validate entity identity bindings.** Reject filename-only bindings and
  synthetic text hashes where a genuine content SHA-1/SHA-256 is required;
  define and test the supported identity contract.
- **Preserve YAML version text.** Keep lexical values such as `1.0` intact
  through parsing, conversion, and serialization rather than silently
  normalizing them.
- **Inherit the solution release version for updated content.** Assign modified
  analytic rules, hunting queries, and other versioned content the version of
  the solution release containing the update. Leave unchanged content versions
  intact and keep source provenance consistent with the actual source version.
- **Default hourly Sentinel rules to the native XDR lookback.** For supported
  rules with a one-hour Sentinel frequency and lookback, retain the hourly
  Custom Detection frequency (`PT1H`) and accept the native four-hour
  ingestion-based lookback without pausing for timing-only approval. Four
  hours is the lookback, not the execution frequency. Preserve the query
  without adding a time filter, and save the source/target timing, exact
  source-document and target-query hashes, applied default, and timing or
  aggregation differences as evidence. Do not claim parity or clear unrelated
  mapping, dependency, KQL, validation, packaging, or environment-write gates.
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
- **Collect review feedback in one consolidated batch.** Prefer one solution-wide
  review packet and one feedback request over serial per-rule or per-workbook
  approval prompts. Inventory all outstanding detection, workbook, dependency,
  timing, entity, version, and content findings before asking. Group repeated
  findings, retain exact affected identities, query pointers and hashes, and
  offer accept/change/defer with per-item exceptions. Preserve previous current
  decisions and record all new decisions as evidence before applying them
  through the supported deterministic commands. Keep technical failures and
  deferred items visible; batch approval does not establish runtime correctness
  or parity, or authorize packaging or environment writes. This is the preferred
  review experience, not a claim that a native unified batch-review CLI exists.
- **Guide users to the next migration blocker review.** End migration status
  updates with a focused next-step recommendation, such as "Next migration step
  can be reviewing blockers A and B." Identify the next blockers and recommended
  review actions rather than overwhelm users with the full issue list, so they
  can stay focused on progressing through the migration.
- **Make sure validation scripts handle XDR Detections and Defender Workbooks
  correctly.** Verify that the official solution validation runner checks both
  content families, reports applicable schema and provenance failures, and keeps
  skipped or unsupported checks visible rather than treating them as passes.
- **Forward explicit approval safely.** Route chat approval to the accountable
  owner while preserving the exact approved operation, scope, and bindings.
- **Clarify execution ownership.** Use appropriate delegation with one owner
  and no duplicate executors for the same operation.
- **Set release-note dates predictably.** Default to today's date unless the
  user explicitly supplies an override.
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
