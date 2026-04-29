---
name: Feature request
about: Suggest a scoped improvement for vuln-prioritizer
title: "[Feature] "
labels: type:feature,status:needs-review
assignees: ""
---

## Problem

What user or maintainer problem does this solve?

## Target

Who needs this, and what decision or workflow should improve?

## Proposed Change

Describe the smallest useful version of the feature.

## Scope

Target surface:

- [ ] CLI/core
- [ ] Template backend API
- [ ] SQLModel/Alembic persistence
- [ ] React frontend
- [ ] Import/parser
- [ ] Provider/enrichment
- [ ] Reports/evidence
- [ ] Governance/security/deployment

## Scope Check

- [ ] this keeps the project focused on prioritizing known CVEs
- [ ] this does not add scanning, exploit execution, PoC generation, active
      probing, credential testing, autopatching, or offensive guidance
- [ ] this does not require heuristic or LLM-generated CVE-to-ATT&CK mapping
- [ ] this does not claim public/shared Workbench readiness without explicit
      threat-model and deployment-hardening work

## Tests

- [ ] unit tests
- [ ] API tests
- [ ] migration tests
- [ ] generated-client drift check
- [ ] browser/Playwright evidence
- [ ] docs check
- [ ] not applicable; rationale:

## Alternatives Considered

What simpler approaches were considered?

## Definition Of Done

- [ ] Acceptance criteria are written in observable terms.
- [ ] Tests or evidence artifacts are named before implementation.
- [ ] API, DB, generated-client, UI, docs, and security impacts are identified.
- [ ] Residual risk and follow-up work are documented.

## Evidence

Provide example commands, report needs, screenshots, API responses, migration
output, generated artifacts, or workflow evidence expected for closure.
