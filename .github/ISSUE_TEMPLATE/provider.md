---
name: Provider or enrichment source
about: Add or change an enrichment provider, cache, snapshot, or freshness workflow
title: "[Provider] "
labels: type:provider,status:needs-review
assignees: ""
---

## Provider Source

Name the provider, endpoint, file format, cache, or snapshot source.

## Target

Which provider, cache, snapshot, CLI command, API route, or report/evidence
surface should change?

## Decision Need

What prioritization, explanation, freshness, or evidence decision should this
provider support?

## Scope

- [ ] new provider/source
- [ ] provider contract change
- [ ] cache or snapshot behavior
- [ ] freshness/status behavior
- [ ] report/API/evidence output
- [ ] docs/support matrix update

## Data Contract

- [ ] Source is official/public or explicitly local.
- [ ] CVE keys and timestamps are clearly defined.
- [ ] Cache and locked-snapshot behavior are documented.
- [ ] Rate limits, authentication, and offline behavior are described.
- [ ] Provider data is context/evidence unless the scoring rule explicitly says
      otherwise.

## Safety Check

- [ ] No remote code execution, plugin loading, exploit lookup, payload fetch, or
      hidden live dependency is introduced.
- [ ] Secrets are read from explicit environment variables and are never logged
      or persisted.
- [ ] Tests can run offline with fixtures.

## Tests

- [ ] fixture-based provider success
- [ ] missing data
- [ ] stale data
- [ ] provider failure/degraded mode
- [ ] cache/snapshot replay
- [ ] docs check

## Definition Of Done

- [ ] Provider fixtures and tests cover success, missing data, stale data, and
      provider failure.
- [ ] Freshness/provenance appears in API/report/evidence output where relevant.
- [ ] Commands run and results are posted before closure.

## Evidence

Paste command results, fixture paths, cache/snapshot metadata, API/report
samples, and residual provider risks.
