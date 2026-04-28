---
name: ATT&CK mapping review
about: Review defensive ATT&CK/TTP context, mapping provenance, or coverage behavior
title: "[ATT&CK] "
labels: type:attack,status:needs-review
assignees: ""
---

## Review Target

Name the mapping file, technique metadata file, coverage report, Navigator layer,
or finding explanation surface.

## Target

Which CVE(s), technique/tactic IDs, mapping file, UI/API/report surface, or
coverage workflow should be reviewed?

## Defensive Purpose

Explain how this helps detection, mitigation, prioritization, or management
explanation. Do not frame mappings as exploit proof.

## Scope

- [ ] mapping provenance review
- [ ] technique metadata review
- [ ] validation command/update
- [ ] Navigator/coverage output
- [ ] finding explanation/report wording
- [ ] docs update

## Source And Provenance

- Mapping source:
- Technique metadata source:
- Version/date/checksum:
- Reviewer:

## Safety Checklist

- [ ] No heuristic, fuzzy, or LLM-generated CVE-to-ATT&CK mapping is introduced.
- [ ] Unmapped CVEs remain explicitly unmapped.
- [ ] The issue does not include exploit payloads, PoC instructions, offensive
      attack-chain guidance, or active exploitation claims.
- [ ] ATT&CK context is presented as defensive context, not proof of active
      exploitation.

## Tests

- [ ] `attack validate`
- [ ] `attack coverage`
- [ ] Navigator layer generation
- [ ] snapshot/report fixture
- [ ] docs check
- [ ] not applicable; rationale:

## Definition Of Done

- [ ] Mapping/provenance evidence is linked or committed.
- [ ] Validation command output is posted.
- [ ] UI/API/report wording stays defensive and avoids overclaiming.

## Evidence

Paste validation output, fixture paths, checksums, screenshots, Navigator layer
paths, or report snippets needed to verify closure.
