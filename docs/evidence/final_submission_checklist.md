# Final Submission Checklist

This checklist is the preserved milestone checklist for the `v0.3.0` ATT&CK extension release package.

Historical note: this checklist tracks the earlier `v0.3.0` submission package. It is intentionally preserved as evidence and is not the current release checklist for the broader `v1.0.0` contract release line.

## Scope Completion

- [x] V0.3 CTID ATT&CK extension implemented
- [x] Local CTID JSON mapping import implemented
- [x] Local ATT&CK technique metadata enrichment implemented
- [x] ATT&CK-aware `analyze`, `compare`, and `explain` outputs implemented
- [x] ATT&CK utility commands implemented: `validate`, `coverage`, `navigator-layer`
- [x] Checked-in ATT&CK fixtures and demo input files added
- [x] Example ATT&CK reports and exports generated
- [x] Documentation updated for methodology, positioning, evidence, and release notes
- [x] Version bumped to `0.3.0`

## Evidence Package

- [x] Current state audit:
  [docs/evidence/current_state_audit.md](./current_state_audit.md)
- [x] Reference gap analysis:
  [docs/reference_cve_prioritizer_gap_analysis.md](../reference_cve_prioritizer_gap_analysis.md)
- [x] Methodology:
  [docs/methodology.md](../methodology.md)
- [x] Executive summary:
  [docs/executive_summary.md](../executive_summary.md)
- [x] Release notes:
  [docs/releases/v0.3.0.md](../releases/v0.3.0.md)
- [x] ATT&CK example report:
  [docs/example_attack_report.md](../example_attack_report.md)
- [x] ATT&CK compare example:
  [docs/example_attack_compare.md](../example_attack_compare.md)
- [x] ATT&CK explain example:
  [docs/example_attack_explain.json](../example_attack_explain.json)
- [x] ATT&CK coverage example:
  [docs/example_attack_coverage.md](../example_attack_coverage.md)
- [x] ATT&CK Navigator layer example:
  [docs/example_attack_navigator_layer.json](../example_attack_navigator_layer.json)

## Verification Gates

- [x] `python3 -m pytest -q`
- [x] `python3 -m pre_commit run --all-files`
- [x] `make check`
- [x] `make release-check`
- [x] `python3 -m build`
- [x] `python3 -m twine check dist/*`

## Submission Talking Points

- [x] The tool remains a CVE prioritizer, not a scanner.
- [x] ATT&CK mappings are imported from CTID artifacts or explicit local files.
- [x] No heuristic or AI-generated CVE to ATT&CK mapping is used.
- [x] ATT&CK adds context and explanation, not the default weighted priority score.
- [x] Unmapped CVEs remain explicitly marked as `Unmapped`.

## Git / Release Publication

- [x] V0.3 implementation committed in Git
- [x] V0.3 branch pushed to GitHub
- [ ] V0.3 integrated onto `main`
- [ ] `v0.3.0` Git tag created
- [ ] `main` and tag pushed to GitHub

## Recommended Submission Bundle

- [x] Repository URL
- [x] Commit hash for final state
- [x] Tag name `v0.3.0`
- [x] Screenshots listed in:
  [docs/evidence/screenshot_capture_list.md](./screenshot_capture_list.md)
- [x] Short verbal story: baseline prioritization, enriched prioritization, ATT&CK context, management decision support
