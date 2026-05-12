## Summary

- what changed
- why it changed

## Linked Issue / Roadmap ID

- Issue:
- VPW ID:
- Intended disposition after merge:

## Scope

- [ ] Domain core
- [ ] Workbench backend API
- [ ] DB/migrations
- [ ] Generated OpenAPI client
- [ ] Manual frontend API wrapper
- [ ] React frontend
- [ ] Docker/Compose
- [ ] Docs/security notes
- [ ] Release/packaging explicitly requested

## Validation

- [ ] `make check` or a scoped equivalent is listed below
- [ ] `make docs-check` for docs changes
- [ ] generated client check for API changes
- [ ] migration/test evidence for DB changes
- [ ] browser/Playwright evidence for UI changes
- [ ] Docker/Compose smoke evidence for Docker/Compose changes
- [ ] release-readiness validation only when this PR is explicitly a release,
      public/shared deployment, or release-evidence change
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

## Scope Guardrails

- [ ] no scanner/asset-discovery scope was introduced
- [ ] no exploit, PoC, active probing, credential testing, offensive
      attack-chain, or autopatching scope was introduced
- [ ] no heuristic or LLM-generated CVE-to-ATT&CK mapping was introduced
- [ ] no secrets, credentials, cookies, customer exports, or private paths are
      exposed in code, logs, screenshots, reports, or docs
- [ ] auth, RBAC, API tokens, multi-user behavior, or public-deployment
      hardening were not added unless the linked issue explicitly asks for them
- [ ] upload limits, rooted artifact paths, and safe parsing are not weakened

## Docs / Release Notes

- [ ] README and changelog were updated if user-visible behavior changed
- [ ] SECURITY/threat model/deployment docs were updated only if a security or
      deployment boundary changed
- [ ] historical template-era, CLI-era, or removed Workbench runtime behavior is
      not used as closure evidence for active Workbench work
