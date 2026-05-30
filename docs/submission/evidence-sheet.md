# Evidence Sheet

This sheet maps the submission's key claims to existing documents and evidence
files. It does not duplicate screenshots.

Archive links in this sheet are historical submission or demo evidence. They
must not be treated as current release certification unless the same claim is
also supported by active code, tests, command output, or an official source in
the [documentation evidence matrix](../documentation-evidence-matrix.md).

## Claim-to-Evidence-Matrix

| Claim | Evidence |
| --- | --- |
| VPW is a workbench for known CVEs, not a scanner. | [README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md), [Security Policy](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md), [Architecture](../architecture.md) |
| The architecture uses FastAPI, React/Vite, a local route adapter, and a generated API client. | [Product Architecture](../architecture.md) |
| The generated client remains the contract boundary, and `api-client.ts` is manual wrapper source. | [Product Architecture](../architecture.md) |
| The backend package intentionally ships both shared domain code and active Workbench app code. | [Dependency and Package Policy](../dependency-and-package-policy.md) |
| Prioritization is transparent and rule-based, not ML/AI-based. | [Scoring Methodology](../scoring-methodology.md) |
| CVSS, EPSS, KEV, asset context, provider freshness, lifecycle, VEX, and waivers are visible. | [Scoring Methodology](../scoring-methodology.md), [Technical Documentation](technical-documentation.md) |
| ATT&CK/TTP is defensive context and does not prove exploitation. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Curated Mapping Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md) |
| Unmapped CVEs remain unmapped; no inference is made. | [ATT&CK/TTP Methodology](../attack-ttp-methodology.md), [Demo Readiness](../demo-readiness.md) |
| Evidence Center creates reports and an evidence bundle with manifest/checksums. | [Reports and Evidence](../reports-and-evidence.md), [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| The demo flow is Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center -> Evidence Bundle. | [Demo Readiness](../demo-readiness.md), [Final Demo Flow](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| The historical final UI flow is documented. | [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md), [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md) |
| CI cost optimization is documented. | [CI Cost Optimization](../ci-cost-optimization.md) |

## Final Demo Flow Evidence

The historical screenshot files were pruned from `main`. The retained summary
documents describe the reviewed flow and point reviewers to regenerate current
screenshots when needed.

- [Demo Flow Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/demo-flow-summary.md)
- [ATT&CK Demo Mapping Summary](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md)

## Presentation Pack

The presentation pack is historical support material for the submission/demo
story. Use current docs and checks for current product claims.

- [Presentation Pack README](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/README.md)
- [Presentation Evidence Index](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/presentation-pack/evidence-index.md)
- [Historical Evidence Manifest](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/archive/vpw-evidence/MANIFEST.md)

## Design-System Proof

The historical visual proof assets were pruned from `main`. Current UI claims
should use current frontend tests, fresh screenshots, or active design docs.

## Contract Artifacts

These files intentionally remain under `docs/evidence/` because backend
contract tests validate them:

- [Analysis result JSON](../evidence/vpw-050-analysis-result.v2.json)
- [Findings CSV](../evidence/vpw-050-findings.csv)
- [Evidence analysis JSON](../evidence/vpw-051-analysis.json)
- [Evidence manifest JSON](../evidence/vpw-051-manifest.json)
- [Positive verification JSON](../evidence/vpw-052-positive-verification.json)
- [Tampered verification JSON](../evidence/vpw-052-tampered-verification.json)
- [Report snapshots](../evidence/vpw-054-report-snapshots.md)
- [ATT&CK Navigator layer](../evidence/vpw-060-attack-navigator-layer.json)

## Reviewer Note

The archived mapping demo for `CVE-2024-4577` is deliberately defensive. It
shows how a reviewed mapping appears in the UI. It does not prove local
compromise and does not contain exploit steps.
