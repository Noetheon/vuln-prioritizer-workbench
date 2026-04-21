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

- [`data/benchmarks/fixture_regressions.json`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/data/benchmarks/fixture_regressions.json)

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

## Maintainer Notes

- Keep the corpus small enough to review, but broad enough to catch contract drift.
- Prefer one good anonymized fixture per meaningful shape over many redundant samples.
- Treat warning-text assertions as contract guardrails for user-visible behavior, not as incidental implementation details.
