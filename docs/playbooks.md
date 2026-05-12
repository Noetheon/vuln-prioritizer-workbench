# Operator Playbooks

These playbooks are the shortest path from "I have findings" to "I know what
to do in the Workbench next".

They are intentionally operator-facing:

- concise
- Workbench-first
- aligned with the local single-user product surface
- cross-linked to deeper reference docs instead of repeating them

Scope note:

- Workbench examples use files you already have locally, such as Trivy, Grype,
  CycloneDX, SPDX, Dependency-Check, Nessus, OpenVAS, VEX, or asset-context
  exports.
- Repo-checkout examples may reference checked-in fixtures under `data/`.
- ATT&CK examples always require reviewed local mapping data.

Use the playbook that matches your workflow:

- [CI and container scanning](playbooks/ci_container_scanning.md)
- [SBOM and dependency triage](playbooks/sbom_triage.md)
- [Infrastructure scan triage](playbooks/infrastructure_scan_triage.md)

Reference material:

- [Support Matrix](support_matrix.md) for supported Workbench inputs, outputs,
  and overlays
- [Contracts](contracts.md) for stable API and report surfaces
- [Reports and Evidence](reports-and-evidence.md) for report artifacts and
  evidence bundles
- [Use Cases](use_cases.md) for the higher-level product story behind these
  workflows
