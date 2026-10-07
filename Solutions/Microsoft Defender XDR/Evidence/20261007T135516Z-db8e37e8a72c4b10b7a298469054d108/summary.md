# Migration evidence — Microsoft Defender XDR

Solution: **Microsoft Defender XDR**
Run: `20261007T135516Z-db8e37e8a72c4b10b7a298469054d108`
Profile: **authoring**
Recorded workflow status: **blocked**
Current solution version at header update: **3.0.18** (not a packaging claim)
Requested version action: **minor**
Requested target solution version: **unknown (not recorded)** (not a packaged version)
Evidence exported at (UTC): **unknown (not recorded)**
Evidence exporter: **sentinel-xdr-migration 0.1.0** (export tool, not historical run version)
Exporter Python: **3.12.7**

Header updated at (UTC): **2026-10-07T15:17:57.291035+00:00**
Header renderer: **sentinel-xdr-migration 0.1.0**
Header-only update: original results, hashes and export identity are preserved;
the current solution version above is a new header observation, not an export-time fact.

**This is a local, curated snapshot, not trusted attestation or a new test run.**
Reported passes are not independently verified. Missing evidence is not a pass.
Content hashes describe export-time bytes, not proof of what historical tests ran.

## All workflow stages

| Stage | Recorded status | Attempts |
| --- | --- | --- |
| discovery | passed | 2 |
| conversion | blocked | 2 |
| validation | pending | 0 |
| packaging | pending | 0 |
| deployment | notRequired | 0 |
| mockIngestion | notRequired | 0 |
| alertParity | notRequired | 0 |
| report | pending | 0 |

## Evidence coverage

| Report | Availability | Recorded status | Items | Recorded item outcomes |
| --- | --- | --- | --- | --- |
| conversion | available | unknown | 40 | converted=25, needsReview=15 |
| structural | missing | unknown | 0 | not-recorded |
| runtimeGraph | missing | unknown | 0 | not-recorded |
| runtimeTriage | missing | unknown | 0 | not-recorded |
| runtimeLogAnalytics | missing | unknown | 0 | not-recorded |
| packaging | missing | unknown | 0 | not-recorded |
| queryParity | missing | unknown | 0 | not-recorded |
| alertParity | missing | unknown | 0 | not-recorded |
| solutionReport | available | unknown | 40 | structural: passed=40 |

See `evidence.json` for every result (including failures, blocks and not-run),
relative paths, hashes, version decisions and provenance mismatches.

Source-query provenance mismatches detected: **0**.
Missing/unsupported provenance remains unverified, even when this count is zero.

## Limitations

- Raw messages, provider records, alerts, credentials and lab identities are omitted.
- Historical commands/tool versions and baseline decisions have no supported persisted contract.
- Historical validation-to-content hash binding is unsupported; current hashes are not attestations.
- Unknown fields/statuses are excluded or marked unknown, never interpreted as success.
- This directory is never read as workflow state or included in Marketplace packages.
