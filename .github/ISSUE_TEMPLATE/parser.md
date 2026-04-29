---
name: Parser or import format
about: Add or change an input parser, normalized occurrence contract, or import workflow
title: "[Parser] "
labels: type:parser,status:needs-review
assignees: ""
---

## Input Source

Name the scanner, SBOM, advisory, or export format.

## Target

Which parser, import path, CLI command, API route, or Workbench workflow should
change?

## Goal

What known-CVE evidence should be normalized and why does this matter for
prioritization?

## Scope

- [ ] new parser/import format
- [ ] existing parser behavior change
- [ ] Workbench import path
- [ ] CLI input validation/normalization
- [ ] schema or contract update
- [ ] documentation/support matrix update

## Sample Shape

Describe the smallest sanitized fixture shape. Do not attach customer exports,
secrets, internal hostnames, tokens, cookies, or private paths.

```json
{}
```

## Normalization Contract

- [ ] CVE extraction is deterministic.
- [ ] Component, package, asset, path, source, fix version, and evidence fields
      are mapped where present.
- [ ] Unsupported or malformed records produce warnings instead of crashes.
- [ ] XML or archive parsing remains safe/local and does not execute content.
- [ ] No live scanner execution or active probing is introduced.

## Tests

- [ ] sanitized valid fixture
- [ ] malformed fixture
- [ ] empty/no-CVE fixture
- [ ] CLI normalization or validation test
- [ ] Workbench import test, if applicable
- [ ] docs/support matrix check

## Definition Of Done

- [ ] Sanitized fixtures are committed.
- [ ] Parser/import tests cover valid, malformed, and empty inputs.
- [ ] CLI and Workbench import behavior stays consistent where applicable.
- [ ] Commands run and results are posted before closure.

## Evidence

Paste command results, fixture paths, normalized output samples, warnings, or API
responses needed to verify closure.
