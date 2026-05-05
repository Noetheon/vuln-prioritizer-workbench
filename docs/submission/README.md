# Submission Package

This package summarizes the current state of Vuln Prioritizer Workbench (VPW)
for the Applied Security Project submission. It links to the existing product
documentation and archived evidence instead of duplicating screenshots or large
artifacts.

## Purpose

VPW is a local, self-hosted workbench for prioritizing already-known CVEs from
existing inputs such as CVE lists, scanner exports, SBOMs, VEX documents, and
asset context. The project is not a scanner, exploit framework, or automatic
intrusion-detection system.

The security value is the traceable decision chain:

```text
Technical finding -> threat signal -> asset context -> business impact
  -> action -> priority -> evidence -> decision
```

## Package Contents

| Document | Purpose |
| --- | --- |
| [Concept](concept.md) | Problem, audience, scope, non-goals, and security value. |
| [Executive Summary](executive-summary.md) | Management-oriented risk-to-decision summary. |
| [Technical Documentation](technical-documentation.md) | Architecture, data flow, imports, scoring, ATT&CK, waivers, reports, and tests. |
| [Evidence Sheet](evidence-sheet.md) | Mapping from claims to evidence files and product documentation. |
| [Demo Script](demo-script.md) | Step-by-step demo flow with fallback, limitations, and speaking notes. |
| [Reviewer Checklist](reviewer-checklist.md) | Review checkpoints before acceptance or presentation. |

## Key Product Documents

- [Product Architecture](../architecture.md)
- [Scoring Methodology](../scoring-methodology.md)
- [ATT&CK/TTP Methodology](../attack-ttp-methodology.md)
- [Reports and Evidence](../reports-and-evidence.md)
- [Demo Readiness](../demo-readiness.md)
- [CI Cost Optimization](../ci-cost-optimization.md)
- [Security Policy](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md)

## Key Evidence Entrypoints

- [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [Curated ATT&CK Demo Mapping](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md)
- [Presentation Pack](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/README.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
- [Historical Evidence Manifest](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/MANIFEST.md)

## Evaluation Boundary

The documentation describes the implemented Workbench state. It does not claim
that VPW scans systems, runs exploits, generates automatic ATT&CK inferences, or
proves local compromise. Prioritization and ATT&CK context remain transparent,
rule-based, and defensive.
