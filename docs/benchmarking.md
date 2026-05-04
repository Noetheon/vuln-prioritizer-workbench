# Benchmarking

This document describes the checked-in regression corpus used by `make benchmark-check`.

## Purpose

The benchmark corpus is not a performance benchmark in the microbenchmark sense.
It is a regression corpus for realistic scanner and SBOM exports that helps catch:

- parsing drift
- warning drift
- unexpected prioritization changes
- fixture regressions across supported input families

## What The Corpus Covers

The current corpus lives in:

- [`data/benchmarks/fixture_regressions.json`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/data/benchmarks/fixture_regressions.json)

It covers three major input families:

- `scanner-json`
- `sbom-json`
- `scanner-xml`

Across those families it exercises all currently supported checked-in example formats:

- `trivy-json`
- `grype-json`
- `cyclonedx-json`
- `spdx-json`
- `dependency-check-json`
- `github-alerts-json`
- `nessus-xml`
- `openvas-xml`

It also includes a dedicated snapshot-diff regression corpus:

- [`data/benchmarks/snapshot_diff_regressions.json`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/data/benchmarks/snapshot_diff_regressions.json)
- before/after fixture pairs under `data/benchmarks/snapshots/`

And a committed remediation-planning rollup fixture:

- [`data/benchmarks/rollup_remediation_analysis.json`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/data/benchmarks/rollup_remediation_analysis.json)

## What Each Benchmark Case Asserts

Each benchmark case records deterministic invariants such as:

- `findings_count`
- `filtered_out_count`
- `occurrences_count`
- `source_stats`
- `counts_by_priority`
- ordered `cve_id` results
- warning substrings for expected edge-case behavior

The benchmark suite intentionally uses the fake-provider path from the test suite so that:

- NVD/EPSS/KEV network drift does not break the benchmark corpus
- failures point to parser and prioritization regressions instead of live-source variance

For `snapshot diff`, the fixture corpus is fully local and deterministic.
It locks down:

- category detection for `added`, `removed`, `priority_up`, `priority_down`, `context_changed`, and `unchanged`
- item ordering in the rendered JSON export
- context-only change detection for all currently supported context fields

For `rollup`, the remediation fixture locks down:

- remediation bucket ordering
- actionable vs total finding counts
- the visible `Unmapped` bucket behavior
- multi-bucket findings that legitimately contribute to more than one service
- structured top-candidate output per bucket

## VPW-072 10k Performance Smoke

`make performance-smoke` runs the optional VPW-072 scale smoke. It is separate
from `make check` so the default developer loop stays fast, but it is available
for release hardening and regression checks.

The smoke generates 10,000 synthetic `generic-occurrence-csv` rows, imports them
through the template Workbench API with locked provider data, verifies that
10,000 findings are persisted, and checks that a high-offset findings page is
stable across repeated requests.

Default MVP thresholds:

- import: 60 seconds or less
- tail-page query: 1 second or less
- process RSS delta: 512 MiB or less

The latest VPW-072 evidence is stored in:

- `archive/vpw-evidence/vpw-072-performance-smoke.md`
- `archive/vpw-evidence/vpw-072-performance-smoke.json`

Known limits: this smoke uses local SQLite and FastAPI `TestClient`. It is not a
Postgres or concurrent-user benchmark. The large all-new bulk path stores compact
score/explain JSON per finding to avoid duplicating full provider payloads across
thousands of repeated occurrences; normalized provider details remain on
vulnerability records.

## Edge-Case Policy

Every major input family must include at least one checked-in edge-case fixture.

For the current corpus, edge coverage comes from realistic exports that already contain:

- non-CVE advisory identifiers such as `GHSA-*`
- duplicate occurrences
- VEX suppression behavior
- XML-specific non-CVE filtering behavior

The goal is to keep the corpus realistic, not synthetic for its own sake.

## Fixture Anonymization Rules

Only commit fixtures that are safe for a public repository.

Required rules:

- remove or replace customer-specific names, IDs, URLs, and repository-private references
- replace real internal hostnames with clearly synthetic examples such as `example.internal`
- replace private IPs with documentation-safe examples such as `192.0.2.0/24`
- preserve the structural shape that exercises the parser
- preserve the warning or prioritization behavior the benchmark is meant to lock down

Avoid:

- raw production exports
- internal ticket references
- internal user names or email addresses
- exploit details that are not necessary for parser behavior

## How To Update The Corpus

When adding or changing a benchmark case:

1. Start from a sanitized fixture under `data/input_fixtures/`.
2. Add or update the case in `data/benchmarks/fixture_regressions.json`.
3. Record the expected warning substrings and output invariants.
4. Run:

```bash
make benchmark-check
make check
```

5. If the fixture is a new supported input shape, also update the normalization contracts and the fixture tests.

When adding snapshot-diff fixtures:

1. Add the before/after JSON files under `data/benchmarks/snapshots/`.
2. Register the pair in `data/benchmarks/snapshot_diff_regressions.json`.
3. Record the exact expected `summary` and simplified `items` output.
4. Keep context-only cases separate from priority-movement cases when that makes failures easier to diagnose.

When updating the rollup remediation fixture:

1. Prefer analysis JSON with realistic saved finding fields over synthetic bucket-only payloads.
2. Keep at least one finding that contributes to multiple assets or services.
3. Keep at least one active `Unmapped` finding and one fully waived bucket.
4. Re-run `make benchmark-check` so ordering and candidate summaries stay stable.

## Maintainer Notes

- Keep the corpus small enough to review, but broad enough to catch contract drift.
- Prefer one good anonymized fixture per meaningful shape over many redundant samples.
- Treat warning-text assertions as contract guardrails for user-visible behavior, not as incidental implementation details.
