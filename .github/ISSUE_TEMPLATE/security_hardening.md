---
name: Security hardening
about: Propose auth, token, upload/download, deployment, audit, or secure-default work
title: "[Security] "
labels: type:security,status:needs-review
assignees: ""
---

## Boundary

What security boundary changes?

## Target

Which route, command, token, upload/download path, deployment setting, report,
evidence artifact, or documentation surface is affected?

## Scope

- [ ] Auth/session/token behavior
- [ ] Upload/import/download/artifact handling
- [ ] API authorization or project access
- [ ] Docker/Compose/deployment configuration
- [ ] Audit/retention/backup/restore
- [ ] Provider/ticket-system integration
- [ ] Documentation/threat model

## Risk

Describe the asset, attacker capability, impact, and current mitigation gap.

## Proposed Hardening

Describe the smallest safe change.

## Tests

- [ ] Targeted tests or smoke checks
- [ ] Threat-model or SECURITY/README update where scope changes
- [ ] API response, migration, browser evidence, or config output where relevant
- [ ] Residual deployment risk documented

## Safety Checklist

- [ ] No public internet readiness is claimed without explicit hardening docs.
- [ ] No secrets, token values, cookies, API keys, customer exports, or private
      paths are exposed.
- [ ] No scanner, exploit, PoC, active probing, credential testing, or
      autopatching behavior is introduced.
- [ ] Upload limits, rooted paths, safe parsing, CSRF-sensitive forms, security
      headers, and token hashing are not weakened.

## Definition Of Done

- [ ] Threat, asset, and boundary are explicitly documented.
- [ ] Security regression test or documented manual evidence is attached.
- [ ] SECURITY.md, README, deployment docs, or threat model are updated if scope
      changed.
- [ ] Commands run and residual risk are posted before closure.

## Evidence

Paste command output, screenshots/traces, API responses, migration/config output,
or threat-model links needed to verify closure. Do not include exploit payloads,
tokens, cookies, customer exports, or private paths.
