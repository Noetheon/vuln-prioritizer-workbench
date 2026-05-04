# Screenshot Capture List

This file lists the recommended screenshots for the preserved `v0.3.0` milestone presentation bundle.

Historical note: this capture list belongs to the earlier `v0.3.0` ATT&CK-extension submission package and is kept for evidence continuity.

## Core CLI Screenshots

1. `python3 -m vuln_prioritizer.cli --help`
   Show the overall command surface including `analyze`, `compare`, `explain`, and `attack`.
2. `python3 -m vuln_prioritizer.cli analyze --help`
   Show the ATT&CK-related CLI options such as `--attack-source`, `--attack-mapping-file`, and `--attack-technique-metadata-file`.
3. `python3 -m vuln_prioritizer.cli analyze --input data/sample_cves_mixed.txt --attack-source ctid-json --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json`
   Capture the terminal table with `ATT&CK` and `Attack Relevance`.
4. `python3 -m vuln_prioritizer.cli compare --input data/sample_cves_mixed.txt --attack-source ctid-json --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json`
   Capture the comparison between CVSS-only and enriched prioritization.
5. `python3 -m vuln_prioritizer.cli explain --cve CVE-2023-34362 --attack-source ctid-json --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json`
   Capture the ATT&CK mapping details for a mapped CVE.

## ATT&CK Utility Screenshots

6. `python3 -m vuln_prioritizer.cli attack validate --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json`
   Show local offline validation of the ATT&CK artifacts.
7. `python3 -m vuln_prioritizer.cli attack coverage --input data/sample_cves_mixed.txt --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json`
   Show mapped versus unmapped coverage.
8. Open [docs/example_attack_navigator_layer.json](../example_attack_navigator_layer.json)
   Show the exported Navigator layer JSON or import it into ATT&CK Navigator and capture that view.

## Artifact Screenshots

9. Open [docs/example_attack_report.md](../example_attack_report.md)
   Capture the ATT&CK summary section in the generated markdown report.
10. Open [docs/example_attack_compare.md](../example_attack_compare.md)
    Capture how ATT&CK context appears in the comparison artifact.
11. Open [docs/example_attack_explain.json](../example_attack_explain.json)
    Capture the structured ATT&CK fields in the JSON output.
12. Open [docs/releases/v0.3.0.md](../releases/v0.3.0.md)
    Capture the release note summary.

## Quality / Evidence Screenshots

13. `python3 -m pytest -q`
    Capture the passing test suite.
14. `make release-check`
    Capture the local release gate result.
15. `git tag --list | grep v0.3.0`
    Capture the release tag after publication.
16. `git log --oneline --decorate -n 5`
    Capture the final commit and branch/tag context.
17. GitHub repository tree on `main`
    Capture the visible repository structure after the push.

## Presentation Framing

- Prefer terminal screenshots with the command line visible.
- Use one screenshot that clearly shows `Unmapped` CVEs, not only mapped cases.
- Include at least one screenshot that demonstrates ATT&CK is contextual and does not silently replace the default score.
- Keep one screenshot focused on management value rather than raw implementation detail.
