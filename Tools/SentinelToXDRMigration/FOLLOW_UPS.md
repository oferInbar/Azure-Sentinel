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

- **Validate entity identity bindings.** Reject filename-only bindings and
  synthetic text hashes where a genuine content SHA-1/SHA-256 is required;
  define and test the supported identity contract.
- **Preserve YAML version text.** Keep lexical values such as `1.0` intact
  through parsing, conversion, and serialization rather than silently
  normalizing them.
- **Reconcile Qualification readiness.** Review existing authorization and
  access checks, then separately assess deployment and ingestion permission
  readiness before proposing new implementation.
- **Review private configuration and support exports.** Reconcile existing
  target-configuration and support-export handling before making claims about
  exposure or adding controls.
- **Improve operator visibility.** Consider concise progress and preflight
  reporting, a workflow diagram, watchdog summaries, and suppression of
  no-change notices.
- **Forward explicit approval safely.** Route chat approval to the accountable
  owner while preserving the exact approved operation, scope, and bindings.
- **Clarify execution ownership.** Use appropriate delegation with one owner
  and no duplicate executors for the same operation.
- **Set release-note dates predictably.** Default to today's date unless the
  user explicitly supplies an override.
- **Evaluate an Author and Validate mode.** A separately approved,
  deployment-only check in a non-production environment could verify
  deployment mechanics. It would not constitute functional/runtime
  qualification, alert-parity evidence, or broader Qualification.

Any future environment write remains separately gated by explicit approval
immediately before the exact operation. No cloud action is authorized by this
roadmap.
