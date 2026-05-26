# Demo Readiness

This page summarizes the current VPW demo story and the evidence files that
support it. It is intended for maintainers, technical reviewers, and Applied
Security Project review.

## Primary Demo Flow

Use the Workbench as the first-screen experience. The canonical demo story is
**Online Shop Demo Workspace**, a local risk operations review built from the
checked-in occurrence CSV, OpenVEX file, locked provider snapshot, curated
ATT&CK mapping, and seeded accepted-risk decisions.

1. **Projects**: create or select a project.
2. **Imports**: import CVE, scanner, SBOM, generic occurrence CSV, and optional
   VEX or asset-context inputs.
3. **Findings**: review the remediation queue, filters, sort, priority, EPSS,
   CVSS, KEV, status, and "Why now" context. Repeated CVEs are visible here as
   occurrence evidence; executive reporting groups them into campaigns.
4. **Finding Detail**: inspect hero metrics, priority explanation, evidence,
   TTP Context, and history.
5. **TTP Context**: show the no-inference state for unmapped findings and the
   curated mapped demo proof when available.
6. **Waivers**: review accepted-risk decisions with owner, scope, expiry,
   review date, and waiver debt. The demo includes active, expiring-soon, and
   review-due states.
7. **Evidence Center**: generate reports and inspect checksum metadata.
8. **Evidence Bundle**: download and verify the ZIP bundle manifest.

The flow demonstrates prioritization of known CVEs. It does not scan targets or
prove exploitability.

## Evidence References

Use these archived entrypoints for proof and presentation planning:

| Flow area | Evidence reference |
| --- | --- |
| End-to-end demo summary | `archive/vpw-evidence/final-demo-flow/demo-flow-summary.md` |
| Curated mapped TTP proof | `archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md` |
| Presentation package overview | `archive/vpw-evidence/presentation-pack/README.md` |
| Presentation evidence index | `archive/vpw-evidence/presentation-pack/evidence-index.md` |
| Historical milestone manifest | `archive/vpw-evidence/MANIFEST.md` |
| Contract report snapshots | `docs/evidence/vpw-054-report-snapshots.md` |
| Evidence bundle manifest contract | `docs/evidence/vpw-051-manifest.json` |
| Positive verification contract | `docs/evidence/vpw-052-positive-verification.json` |
| Tamper verification contract | `docs/evidence/vpw-052-tampered-verification.json` |
| ATT&CK Navigator contract | `docs/evidence/vpw-060-attack-navigator-layer.json` |

These references are deliberately split: current contract artifacts stay in
`docs/evidence/`, while broad screenshots and milestone proof stay in
`archive/vpw-evidence/`.

## Demo TTP States

Two TTP states should be shown:

- **No inference**: unmapped CVEs remain unmapped. The UI should make it clear
  that VPW did not guess tactics or techniques.
- **Mapped proof**: the curated demo mapping for `CVE-2024-4577` can show
  technique, tactic, confidence, source, coverage, and safety wording.

Both states should keep the defensive boundary visible. A mapped ATT&CK
technique is not proof of local exploitation, and an unmapped finding is not
safe by default.

## Demo Data Contract

- Backend persisted demo: `data/input_fixtures/demo_workspace_occurrences.csv`,
  `data/input_fixtures/demo_workspace_openvex.json`,
  `data/demo_provider_snapshot.json`, `data/attack/local_curated_demo_mappings.yml`,
  and seeded waivers in the Workbench service.
- Frontend demo entry: the Dashboard shows **Load demo workspace** only when the
  local backend exposes `/api/v1/workbench/demo` with
  `DEMO_WORKSPACE_ENABLED=true`; all follow-up data comes from persisted
  project, run, waiver, finding, and report APIs.
- Core CVEs: `CVE-2020-1472`, `CVE-2021-44228`, `CVE-2022-22965`,
  `CVE-2023-34362`, `CVE-2023-44487`, `CVE-2024-3094`, and `CVE-2024-4577`.
- Controlled imperfections are intentional: locked replay is reproducible but
  not automatically fresh, governance review is due, VEX/fixed evidence remains
  visible, and unmapped CVEs remain unmapped.

## Readiness Checks

Before a final demo or review, use a small stability sample:

- frontend build, lint, unit tests, and UI smoke
- backend Workbench/API smoke subset
- backend report contract tests
- docs hygiene and MkDocs build
- evidence bundle verification for any newly generated bundle

Avoid adding fresh screenshots during routine documentation work unless a visual
regression needs diagnosis. Screenshots used for final presentation should be
captured intentionally and indexed in the archive or presentation pack.

## Known Limitations

- Demo data is sample data and must be labeled as such.
- Provider freshness depends on selected local or live provider data.
- ATT&CK mapping is explicit and source-backed; VPW does not infer missing
  mappings.
- Detection coverage is defensive review context, not proof that controls are
  effective against a real intrusion.
- The built-in Workbench is self-hosted/local-first; public deployment still
  needs separate hardening and operational review.
