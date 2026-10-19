# Toolkit Security & Privacy Review Summary

**Branch:** `toolkit/qualification-and-followups` (compared against `upstream/master`)  
**Date:** 2026-10-19

## Security Review Findings

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | `Tools/SentinelToXDRMigration/solution_manager/qualification/pr_check_runner.py` | 680-790, 2962-2978 | Untrusted solution-tree `Evidence/qualification-evidence.json` `checks.<checkId>` override can short-circuit deterministic validation checks without executing them | 9/10 |
| 2 | 🟠 HIGH | `Tools/SentinelToXDRMigration/solution_manager/qualification/templates/grant-graph-hunting-scopes.bicep` | 4-70 | Graph scope remediation template defaults to `consentType: 'AllPrincipals'`, `grantToAzureCli: true`, and unconstrained `delegatedScopes` string | 8/10 |

---

### Finding 1 — Solution-Tree `checks.<checkId>` Override Short-Circuits Deterministic Checks
- **Location:** `Tools/SentinelToXDRMigration/solution_manager/qualification/pr_check_runner.py` (lines 680–790, 2962–2978)
- **Category:** `DataIntegrityFailure`
- **Details:** `evaluate_solution_pr_qualification` automatically loads `Evidence/qualification-evidence.json` from the solution folder. `_check_direct_override` accepts `checks.<checkId>` or top-level `<checkId>` status overrides, and `_apply_override_if_present` allows those overrides to replace deterministic Validation/Migration check execution. Also ensure `HUMAN_REVIEW_REQUIRED` checks (`QUAL-HR-01`, `QUAL-RULE-01`, `QUAL-TEXT-01`, `QUAL-RELEASE-01`) cannot be auto-bypassed to `PASS` via `checks.<checkId>` without reviewer sign-off.
- **Planned Fix for Tomorrow:**
  1. Never allow `qualification_evidence` (`checks.<checkId>`) to override deterministic `Validation` checks (`E2E-V*`, `TK-V*`, `MIG-V*`) or bypass `HUMAN_REVIEW_REQUIRED` sign-off items (`QUAL-HR-01`, `QUAL-RULE-01`, `QUAL-TEXT-01`, `QUAL-RELEASE-01`).
  2. Restrict `qualification_evidence` usage to live runtime/lab receipts (`deployment`, `mockIngestion`, `alertLifecycle`, `alertParity`, `workbookQualification`, `dualSurfaceKql`, `urlVerification`) and verify receipt structure rather than trusting bare `status: "PASS"` strings.

---

### Finding 2 — Over-Broad Defaults in `grant-graph-hunting-scopes` Remediation Template
- **Location:**
  - `Tools/SentinelToXDRMigration/solution_manager/qualification/templates/grant-graph-hunting-scopes.bicep` (lines 4–70)
  - `Tools/SentinelToXDRMigration/solution_manager/qualification/templates/grant-graph-hunting-scopes.arm.json`
  - `Tools/SentinelToXDRMigration/solution_manager/qualification/delegated_app_registration.py` (lines 73–127)
- **Category:** `SecurityMisconfiguration`
- **Details:** The optional Bicep/ARM template for granting delegated Microsoft Graph scopes defaults `grantToAzureCli` to `true`, uses `consentType: 'AllPrincipals'`, and accepts an unconstrained `delegatedScopes` string.
- **Planned Fix for Tomorrow:**
  1. Default `grantToAzureCli` to `false` and support principal-scoped (`consentType: 'Principal'` with `principalId`) or explicit least-privilege consent.
  2. Constrain `delegatedScopes` to the allowed hunting/custom-detection scope set (`ThreatHunting.Read.All`, `CustomDetection.ReadWrite.All`).

---

## Privacy, PII & Secrets Scan Summary

- **Changed Toolkit Files Scanned (`upstream/master...HEAD`):** 69 files across `Tools/`, `.github/`, `AGENTS.md`, `CLAUDE.md`, and `.gitignore`.
- **Local Machine Paths (`/Users/...`, `C:\Users\...`):** `0` leaks (only synthetic `/Users/secadmin` and `/Users/developer` test fixtures in `test_decision_manifest.py`).
- **Tenant / Subscription / Workspace GUIDs:** `0` hardcoded lab IDs in toolkit code.
- **Personal Emails / Credentials / Tokens:** `0` leaks (only `support@microsoft.com` in test fixtures).
