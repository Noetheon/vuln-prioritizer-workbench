---
name: Bug report
about: Report a defect or behavioral regression in vuln-prioritizer-workbench
title: "[Bug] "
labels: bug,status:needs-revalidation
assignees: ""
---

## Summary

Describe the defect clearly and concretely.

## Target

What Workbench workflow, backend API route, frontend page, package, or release
path is affected?

## Affected Surface

- [ ] Workbench backend API
- [ ] Active Workbench UI/API
- [ ] React frontend
- [ ] Docker/Compose
- [ ] Docs/release/packaging
- [ ] Security/deployment

## Scope / Impact

What is broken, how severe is it, and what should stay unchanged?

## Reproduction

Steps:

```bash
# paste exact local commands only when they are needed to reproduce the issue
```

## Observed Behavior

What happened?

## Expected Behavior

What should have happened instead?

## Environment

- Python version:
- OS:
- `vuln-prioritizer-workbench` version/tag:

## Tests

- [ ] regression test
- [ ] parser fixture
- [ ] API test
- [ ] migration test
- [ ] browser/Playwright smoke
- [ ] docs check
- [ ] not applicable; rationale:

## Definition Of Done

- [ ] Root cause is identified or the issue is linked to a narrower follow-up.
- [ ] Regression test, parser fixture, API test, Playwright smoke, or docs proof
      is added where relevant.
- [ ] Fixed behavior is described in observable terms.
- [ ] Commands run and results are posted before closure.
- [ ] No secrets, customer scanner exports, tokens, cookies, or private paths are
      included in public evidence.
- [ ] Auth/RBAC/API-token, multi-user, or public-deployment scope is not added
      unless the issue explicitly asks for that boundary.

## Evidence

- terminal output
- stack trace
- input file shape
- optional screenshots or report snippets
