# Historical Evidence Archive

This file lists historical repository artifacts that are useful for demonstrations, evaluation, or handoff.

Historical note: this evidence pack was originally assembled for the ATT&CK-focused `v0.3.0` milestone. The broader release line has since moved forward, so this page should be treated as an archive rather than the primary product documentation surface.

## Visible Artifacts

- CLI base flow: `vuln-prioritizer analyze`
- comparison flow: `vuln-prioritizer compare`
- single-CVE deep dive: `vuln-prioritizer explain --cve ...`
- ATT&CK validation: `vuln-prioritizer attack validate`
- ATT&CK coverage summary: `vuln-prioritizer attack coverage`
- ATT&CK Navigator export: `vuln-prioritizer attack navigator-layer`

Example inputs:

- [`data/sample_cves.txt`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/sample_cves.txt)
- [`data/sample_cves_attack.txt`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/sample_cves_attack.txt)
- [`data/sample_cves_mixed.txt`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/sample_cves_mixed.txt)
- [`data/optional_attack_to_cve.csv`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/optional_attack_to_cve.csv)
- [`data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json)
- [`data/attack/attack_techniques_enterprise_16.1_subset.json`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/attack/attack_techniques_enterprise_16.1_subset.json)

Example outputs:

- [docs/example_report.md](./example_report.md)
- [docs/example_compare.md](./example_compare.md)
- [docs/example_explain.json](./example_explain.json)
- [docs/example_attack_report.md](./example_attack_report.md)
- [docs/example_attack_compare.md](./example_attack_compare.md)
- [docs/example_attack_explain.json](./example_attack_explain.json)
- [docs/example_attack_coverage.md](./example_attack_coverage.md)
- [docs/example_attack_navigator_layer.json](./example_attack_navigator_layer.json)

Supporting docs:

- [docs/methodology.md](./methodology.md)
- [docs/executive_summary.md](./executive_summary.md)
- [docs/evidence/current_state_audit.md](./evidence/current_state_audit.md)
- [docs/evidence/final_submission_checklist.md](./evidence/final_submission_checklist.md)
- [docs/evidence/screenshot_capture_list.md](./evidence/screenshot_capture_list.md)
- [docs/reference_cve_prioritizer_gap_analysis.md](./reference_cve_prioritizer_gap_analysis.md)

## Recommended Historical Evidence Collection

1. Screenshot of `python3 -m vuln_prioritizer.cli --help`
2. Screenshot of `analyze` with `--attack-source ctid-json`
3. Screenshot or export of [docs/example_attack_report.md](./example_attack_report.md)
4. Screenshot or export of [docs/example_attack_compare.md](./example_attack_compare.md)
5. Screenshot or export of [docs/example_attack_explain.json](./example_attack_explain.json)
6. Screenshot of `attack coverage`
7. Screenshot of the generated Navigator layer JSON or ATT&CK Navigator import
8. `pytest` output
9. `make release-check` output
10. release notes from [docs/releases/v0.3.0.md](./releases/v0.3.0.md)

## Suggested Demo Story

- Start with the baseline report to show CVSS/EPSS/KEV enrichment.
- Show `compare` to explain why the enriched model differs from `CVSS-only`.
- Switch to the ATT&CK-aware report and coverage summary to show mapped versus unmapped CVEs.
- Use `explain` on a mapped CVE to demonstrate the threat-informed context layer.
- Close with the Navigator layer and management-facing summary.

## Evidence Boundaries

- ATT&CK evidence must come from the checked-in CTID and ATT&CK metadata files or explicitly provided local files.
- Do not present heuristic or AI-generated ATT&CK mappings as authoritative evidence.
- Be explicit when a CVE is `Unmapped`.
