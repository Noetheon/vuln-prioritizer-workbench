# SBOM Dependency Triage Playbook

Use this playbook when the input is an SBOM or dependency-analysis export and the goal is to move from a flat advisory list to an explainable remediation queue.

This is the narrow operator path for:

- `cyclonedx-json`
- `spdx-json`
- `dependency-check-json`
- comparison, snapshot, and rollup follow-through

For the broader product surface, see:

- [Use cases](../use_cases.md)
- [Support matrix](../support_matrix.md)
- [Methodology](../methodology.md)

## When to use this path

Choose this workflow when:

- the starting artifact is a dependency or SBOM export
- package context matters as much as raw CVSS
- you want to compare CVSS-only intuition against the enriched result
- teams need a saved JSON artifact for later diffing or rollup

## Fast comparison run

Start with `compare` if the team wants to understand what enrichment changed before introducing a new gate.

CycloneDX fixture example:

```bash
vuln-prioritizer compare \
  --input data/input_fixtures/cyclonedx_bom.json \
  --input-format cyclonedx-json \
  --format markdown \
  --output build/sbom-compare.md
```

Dependency-Check fixture example:

```bash
vuln-prioritizer compare \
  --input data/input_fixtures/dependency_check_report.json \
  --input-format dependency-check-json \
  --format markdown \
  --output build/dependency-check-compare.md
```

Use this stage to answer:

- which findings moved because of KEV or EPSS
- which findings stayed flat despite high raw severity
- whether the current policy profile is acceptable before introducing a fail gate

## Save a reusable analysis artifact

Once the team is comfortable with the prioritization logic, switch to `analyze` and keep JSON as the durable artifact:

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/cyclonedx_bom.json \
  --input-format cyclonedx-json \
  --format json \
  --output build/sbom-analysis.json \
  --summary-output build/sbom-summary.md
```

Why this matters:

- the JSON report is the stable machine contract
- the summary is enough for reviewer-facing handoff
- package names, versions, paths, and fix hints remain visible from the source export

## Add a point-in-time snapshot

If dependency triage is recurring, save a snapshot after each meaningful run:

```bash
vuln-prioritizer snapshot create \
  --input data/input_fixtures/cyclonedx_bom.json \
  --input-format cyclonedx-json \
  --output build/sbom-snapshot.json
```

Then compare two saved states:

```bash
vuln-prioritizer snapshot diff \
  --before build/before-sbom-snapshot.json \
  --after build/sbom-snapshot.json \
  --format markdown \
  --output build/sbom-diff.md
```

This is the right path when teams ask:

- what is new
- what got worse
- what disappeared
- what changed because context changed rather than priority alone

## Roll up by service when ownership matters

If asset or service ownership is available in the saved analysis or snapshot, aggregate findings before scheduling work:

```bash
vuln-prioritizer rollup \
  --input build/sbom-analysis.json \
  --by service \
  --format markdown \
  --output build/sbom-rollup.md
```

Use rollups when the question is no longer "which CVE is bad?" but "which team or service should move first?"

## Suggested operator sequence

1. Run `doctor` if runtime config, cache health, or local files look suspicious.
2. Start with `compare` when you need adoption buy-in.
3. Move to `analyze --format json` once the team wants a durable contract.
4. Add `snapshot create` for recurring triage.
5. Add `snapshot diff` once before/after questions appear in review.
6. Add `rollup` when remediation ownership matters more than a flat CVE list.

## What to review in SBOM outputs

Focus on:

- package and version context
- fix hints or upgrade clues preserved from the source export
- KEV and EPSS signals that move a dependency issue up
- repeated problem areas that should become service-level remediation work

If a single CVE remains contentious, use `explain` rather than trying to infer the decision only from the aggregate markdown report.

## Notes

- Plain BOMs without vulnerability records are not the target workflow here.
- Keep `--input-format` explicit in automation.
- If this becomes a recurring team workflow, move stable defaults into `vuln-prioritizer.yml` rather than relying on ad hoc shell history.
