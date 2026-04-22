# Infrastructure Scan Triage

Use this playbook when you already have a Nessus or OpenVAS export and want to turn it into a local, reproducible triage workflow with optional asset context and optional ATT&CK context.

This is a prioritization flow for known CVEs. It does not replace the scanner, and it only normalizes scanner records that can be resolved to CVE IDs.

All commands below assume you are running from the repository root.

## Before You Start

- Run `doctor` first if the runtime config, cache, local files, or live feed reachability are uncertain.
- Prefer an explicit `--input-format` in CI and repeated operator workflows.
- Treat ATT&CK as an explicit context layer. It does not silently replace the base `CVSS + EPSS + KEV` priority model.
- Expect `Unmapped` rollup buckets until your asset context matches the normalized scanner targets exactly.

## Checked-In Inputs You Can Reuse

- Nessus fixture: `data/input_fixtures/nessus_report.nessus`
- OpenVAS fixture: `data/input_fixtures/openvas_report.xml`
- Asset-context schema example: `data/input_fixtures/example_asset_context.csv`
- ATT&CK mapping fixture: `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`
- ATT&CK technique metadata fixture: `data/attack/attack_techniques_enterprise_16.1_subset.json`

The checked-in asset-context CSV documents the column shape, but its sample row is image-focused. For real infrastructure triage, copy that schema and replace it with host or service identifiers that match your scanner-derived `target_kind` values and either exact or glob-style `target_ref` values, using `precedence` when multiple rules could overlap.

## 1. Validate the Operator Environment

Run the local health check first:

```bash
vuln-prioritizer doctor
```

If you plan to add ATT&CK context, validate those local files before using them in `analyze`:

```bash
vuln-prioritizer attack validate \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

## 2. Produce a Baseline Analysis

Pick the scanner export you actually have. Use JSON output as the durable artifact, then add Markdown summary and HTML sidecars for operator review.

Nessus example:

```bash
mkdir -p build

vuln-prioritizer analyze \
  --input data/input_fixtures/nessus_report.nessus \
  --input-format nessus-xml \
  --format json \
  --output build/nessus-analysis.json \
  --summary-output build/nessus-summary.md \
  --html-output build/nessus-report.html
```

OpenVAS example:

```bash
mkdir -p build

vuln-prioritizer analyze \
  --input data/input_fixtures/openvas_report.xml \
  --input-format openvas-xml \
  --format json \
  --output build/openvas-analysis.json \
  --summary-output build/openvas-summary.md \
  --html-output build/openvas-report.html
```

What to expect:

- Only CVE-resolvable findings are normalized into the prioritization pipeline.
- Non-CVE scanner records are intentionally filtered out.
- The saved JSON is the main machine-readable artifact for later rollups, evidence bundles, and diffs.

## 3. Add Asset Context Deliberately

Asset context is only useful when the join is exact on `(target_kind, target_ref)`. Start from the checked-in CSV schema, adapt it to your infrastructure targets, then rerun `analyze` with `--asset-context`.

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/openvas_report.xml \
  --input-format openvas-xml \
  --asset-context path/to/asset_context.csv \
  --format json \
  --output build/openvas-analysis.json \
  --summary-output build/openvas-summary.md \
  --html-output build/openvas-report.html
```

If later rollups still show a large `Unmapped` bucket, fix the asset-context join first before treating service-level rankings as complete.

## 4. Add ATT&CK Context Only When You Need It

Prefer `ctid-json`. The older `local-csv` mode is a compatibility fallback, not the recommended workflow.

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/openvas_report.xml \
  --input-format openvas-xml \
  --asset-context path/to/asset_context.csv \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json \
  --format json \
  --output build/openvas-analysis.json \
  --summary-output build/openvas-summary.md \
  --html-output build/openvas-report.html
```

Use ATT&CK here when you need additional operator context for exposure, tactics, or downstream reporting. Keep the decision model interpretation the same: ATT&CK explains and contextualizes; it does not become a hidden score override.

## 5. Aggregate to the Remediation Layer

Once you have a saved analysis JSON, move from flat CVE output to asset or service buckets.

Service rollup:

```bash
vuln-prioritizer rollup \
  --input build/openvas-analysis.json \
  --by service \
  --format markdown \
  --output build/openvas-rollup-service.md
```

Asset rollup:

```bash
vuln-prioritizer rollup \
  --input build/openvas-analysis.json \
  --by asset \
  --format markdown \
  --output build/openvas-rollup-asset.md
```

Use the rollup output to answer the operational question that matters most: which service or asset group should be patched first, and which CVEs are driving that urgency.

## 6. Build a Reviewable Handoff Artifact

When the triage result needs to leave the local workspace, create an evidence bundle and verify it before sharing.

```bash
vuln-prioritizer report evidence-bundle \
  --input build/openvas-analysis.json \
  --output build/openvas-evidence.zip

vuln-prioritizer report verify-evidence-bundle \
  --input build/openvas-evidence.zip \
  --format json \
  --output build/openvas-evidence-verification.json
```

This gives you a reproducible package containing the saved analysis, regenerated report artifacts, and manifest-backed integrity metadata.

## Operator Notes

- Use `doctor` as the first troubleshooting command.
- Use `attack validate` before an ATT&CK-enabled run whenever local mapping files change.
- Use `snapshot create` and `snapshot diff` if you need to compare two scan points in time rather than triage one export in isolation.
- Prefer JSON as the stored source of truth and treat Markdown and HTML as review surfaces built from that saved result.

## Related Docs

- [Support Matrix](../support_matrix.md)
- [Methodology](../methodology.md)
- [Contracts](../contracts.md)
- [Reporting and CI Integration](../integrations/reporting_and_ci.md)
- [Use Cases](../use_cases.md)
