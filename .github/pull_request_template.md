## Summary

- what changed
- why it changed

## Linked Issue / Roadmap ID

- Issue:
- VPW ID:
- Disposition intended after merge:

## Scope

- [ ] CLI/core
- [ ] Template backend API
- [ ] DB/migrations
- [ ] Generated OpenAPI client
- [ ] React frontend
- [ ] Docker/Compose
- [ ] Docs/governance/security
- [ ] Release/packaging

## Validation

- [ ] `make check` or a scoped equivalent is listed below
- [ ] `make docs-check` for docs changes
- [ ] generated client check for API changes
- [ ] migration/test evidence for DB changes
- [ ] browser/Playwright evidence for UI changes
- [ ] Docker/Compose smoke evidence for runtime/deployment changes
- [ ] additional local validation, if applicable

Commands and results:

```text
paste command output summary here
```

## Evidence

- paths, screenshots, traces, API responses, migration output, or generated
  artifacts:
- residual risk:
- follow-up issues:

## Definition Of Done

- [ ] linked issue scope, acceptance criteria, and evidence requirements are met
- [ ] commands run and results are pasted above
- [ ] evidence artifact paths or screenshots/traces are listed above
- [ ] residual risk and follow-up issues are listed above
- [ ] no issue is closed as `verified-shipped` or `superseded` without fresh
      evidence and explicit rationale in the issue

## Security Review

- [ ] no scanner/asset-discovery scope was introduced
- [ ] no exploit, PoC, active probing, credential testing, offensive
      attack-chain, or autopatching scope was introduced
- [ ] no heuristic or LLM-generated CVE-to-ATT&CK mapping was introduced
- [ ] no secrets, tokens, cookies, customer exports, or private paths are
      exposed in code, logs, screenshots, reports, or docs
- [ ] upload limits, rooted artifact paths, safe parsing, CSRF-sensitive forms,
      security headers, and token hashing are not weakened
- [ ] public/shared Workbench readiness is not claimed without threat-model and
      deployment-hardening updates

## Docs / Release Notes

- [ ] README and changelog were updated if user-visible behavior changed
- [ ] SECURITY/threat model/deployment docs were updated if a security boundary
      changed
- [ ] old Jinja2/SQLAlchemy Workbench behavior is not used as automatic closure
      evidence for template React/JWT/SQLModel work
