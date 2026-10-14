# Handoff Guide: Microsoft Defender XDR 3.2.1 Migration

## 1. Repository & Branches (`oferInbar/Azure-Sentinel`)
- **Toolkit Branch:** `solution-toolkit-defender-wbs` (PR `#4`: https://github.com/oferInbar/Azure-Sentinel/pull/4, commit `e0528222a1`)
- **Solution Content & State Branch:** `content/defender-xdr-3-2-1`
- **Active Run ID:** `20261014T114522Z-55dd62367c044891b40892318b184efe`
- **Solution Path:** `Solutions/Microsoft Defender XDR`

## 2. Quick Setup (to have both the toolkit and the Defender XDR content in one checkout)
```bash
git clone https://github.com/oferInbar/Azure-Sentinel.git
cd Azure-Sentinel
git checkout content/defender-xdr-3-2-1

# Merge or checkout the toolkit files from solution-toolkit-defender-wbs:
git checkout origin/solution-toolkit-defender-wbs -- Tools/ .github/ .script/local-validation/ AGENTS.md CLAUDE.md
python -m pip install -e Tools/SentinelToXDRMigration
```

## 3. What Has Already Been Completed & Approved by Ofer
All of Ofer's consolidated review decisions are committed and applied in this branch:
- **40 XDR Detection drafts** under `Solutions/Microsoft Defender XDR/XDR Detections/` (all disabled, `version: 3.2.1`):
  - **18 rules `converted`** (ready)
  - **22 rules `needsReview` (`reviewRequired: true`)**
- **Applied Detection Approvals:**
  - **26 timing approvals** (8 prior + 10 `PT1H` hourly + 8 `P1D` daily, unchanged KQL).
  - **21 provisional host-mapping approvals** (17 `DeviceName`, 3 `CompromisedEntity`, 1 `Dvc`, retaining output-column bindings and correlation warnings).
  - **7 full alert descriptions** replacing truncated `...` source descriptions.
  - **AWSS3 `dataTypes` casing fix** in `XDR Detections/PossiblePhishingwithCSL&NetworkSession.yaml` (preserving Sentinel source YAML unchanged).
- **ASIM Built-In Standard Parsers Verified:**
  - Ofer verified in live Defender XDR Custom Detection `122668` that standard built-in ASIM parsers starting with `_` (`_ASim_ProcessEvent` in `Campaign/Macaw Ransomware/ImminentRansomware.yaml` and `_Im_NetworkSession` in `PossiblePhishingwithCSL&NetworkSession.yaml`) are supported in Advanced Hunting, Custom Detections, and Defender Workbooks.
- **3 XDR Workbook drafts** under `Solutions/Microsoft Defender XDR/XDR Workbooks/`:
  - `MicrosoftDefenderForEndPoint.json`
  - `MicrosoftDefenderForIdentity.json`
  - `MicrosoftDefenderForOffice365detectionsandinsights.json`
  - 24 static table resolutions recorded in `offline-workbook-review/workbook-review-receipt.json` (including MDO native tables `MessageEvents`, `MessageUrlInfo`, `MessagePostDeliveryEvents`, `FileMaliciousContentInfo`).

## 4. Key Review Artifacts in This Run Folder
- `workflow-state.json` — Canonical resumable state for run `20261014T114522Z-55dd62367c044891b40892318b184efe`.
- `consolidated-review-packet.json` & `consolidated-review-response.json` — Ofer's one-shot review packet and recorded answers.
- `authoring-review-config.json` & `offline-review-application-receipt.json` — Applied configuration and SHA-256 verification receipt.
- `offline-review-remaining-decisions.json` — Exact breakdown of the remaining 22 `needsReview` detections (primarily 21 rules retaining `reviewRequired` from provisional host-entity assumptions / custom detail bindings, plus the 2 ASIM rules) and remaining workbook query items.

## 5. Before Opening the Final Upstream PR to `Azure/Azure-Sentinel`
Because `Solutions/Microsoft Defender XDR/Logs/` was force-added (`git add -f`) specifically so you receive `workflow-state.json` and the approval receipts, remove `Logs/` from git tracking before opening the upstream PR:
```bash
git rm -r --cached "Solutions/Microsoft Defender XDR/Logs"
git commit -m "Remove local migration logs before upstream PR"
```
