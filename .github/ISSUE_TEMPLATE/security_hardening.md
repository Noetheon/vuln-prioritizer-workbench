---
name: Security hardening
about: Propose local access, upload/download, deployment, audit, or secure-default work
title: "[Security] "
labels: type:security,status:needs-review
assignees: ""
---

## Boundary

What security boundary changes?

## Target

Which route, API endpoint, upload/download path, deployment setting, report,
evidence artifact, or documentation surface is affected?

## Scope

- [ ] Local access behavior
- [ ] Shared-deployment behavior explicitly requested
- [ ] Upload/import/download/artifact handling
- [ ] Local API exposure or project data access
- [ ] Docker/Compose/deployment configuration
- [ ] Audit/retention/backup/restore
- [ ] Provider/ticket-system integration
- [ ] Documentation/threat model

## Risk

Describe the asset, attacker capability, impact, and current mitigation gap.

## Proposed Hardening

Describe the smallest safe change.

Auth, RBAC, API tokens, multi-user operation, and public-deployment hardening are
future/explicit tracks. Do not add them to ordinary product work by implication.

## Tests

- [ ] Targeted tests or smoke checks
- [ ] Threat-model or SECURITY/README update where scope changes
- [ ] API response, migration, browser evidence, or config output where relevant
- [ ] Residual deployment risk documented

## Safety Checklist

- [ ] Public/shared deployment certification is only claimed when that track is
      explicitly requested and backed by dedicated evidence.
- [ ] No secrets, credentials, cookies, API keys, customer exports, or private
      paths are exposed.
- [ ] No scanner, exploit, PoC, active probing, credential testing, or
      autopatching behavior is introduced.
- [ ] Upload limits, rooted paths, safe parsing, CSRF-sensitive forms, security
      headers, and credential handling are not weakened.

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
