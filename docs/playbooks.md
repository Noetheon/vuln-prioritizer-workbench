# Operator Playbooks

These playbooks are the shortest path from "I have findings" to "I know what to run next".

They are intentionally operator-facing:

- concise
- command-first
- aligned with the current public CLI surface
- cross-linked to the deeper reference docs instead of repeating them

Use the playbook that matches your workflow:

- [CI and container scanning](playbooks/ci_container_scanning.md)
- [SBOM and dependency triage](playbooks/sbom_triage.md)
- [Infrastructure scan triage](playbooks/infrastructure_scan_triage.md)

Reference material:

- [Support Matrix](support_matrix.md) for supported inputs, outputs, and feature overlays
- [Contracts](contracts.md) for stable machine-readable surfaces
- [Reporting and CI Integration](integrations/reporting_and_ci.md) for SARIF, summaries, HTML, and GitHub Action patterns
- [Use Cases](use_cases.md) for the higher-level product story behind these workflows
