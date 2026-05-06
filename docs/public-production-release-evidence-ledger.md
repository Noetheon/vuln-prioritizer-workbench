# Public-Production Release Evidence Ledger

This ledger tracks the public-production readiness evidence story without
claiming final readiness before PP5 acceptance. It is a public-safe index for
commands, generated artifacts, package boundaries, and residual risks.

## Acceptance Boundary

Public-production readiness is not claimed until
[#350](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/350)
closes with a final scorecard and evidence links. Until then, this document is
a readiness ledger and release-target checklist, not a certification.

Evidence added to public docs must avoid secrets, tokens, cookies, customer
exports, private absolute paths, and shell history. Current contract artifacts
belong in `docs/evidence/`; screenshots, historical issue proof, and broader
validation logs belong under `archive/vpw-evidence/` or external CI artifacts
linked from an issue or PR.

## Selected Package and Runtime Story

- The active browser Workbench runtime is `backend/app`.
- The Python distribution intentionally ships both `backend/app/**` and
  `backend/src/vuln_prioritizer/**`.
- The frontend generated OpenAPI client is `frontend/src/client/**`.
- `frontend/src/api-client.ts` is a manual wrapper over the generated client,
  not generated output.
- `frontend/package-lock.json` is the audited frontend lockfile.
- The root `bun.lock` is retained for Bun-compatible convenience scripts, not
  as the release audit source.

## Release-Readiness Targets

| Target | Purpose | Evidence |
| --- | --- | --- |
| `make dependency-audit` | Backend and frontend dependency audit | `pip-audit` on `backend/requirements.txt`; npm audit on `frontend/package-lock.json` |
| `make package-check` | Build, package-content, and metadata validation | `dist/*`, `twine check`, `build/package-contents.json` |
| `make pipx-source-smoke` | Source-at-tag install path compatibility | pipx smoke output and generated smoke artifacts |
| `make api-client-drift-check` | OpenAPI/generated-client compatibility | `scripts/generate-client.sh`; clean `frontend/src/client` diff |
| `make docs-check` | Public documentation build | clean MkDocs build |
| `make demo-evidence-bundle-check` | Evidence bundle integrity | `build/v1.0-demo-evidence-bundle-verification.json` |
| `make docker-demo-smoke` | Compose runtime smoke | backend/frontend health plus import/provider smoke |
| `make docker-production-smoke` | Production-like same-origin smoke | production env, non-default secrets, CSP, cookies, CSRF, health/status split, import, report download, logout |
| `make playwright-check` | Browser smoke and accessibility path | frontend Playwright smoke, responsive shell, and Axe no serious/critical violations |
| `make release-readiness-check` | Full local readiness handoff | release gate, client drift, evidence bundle, Playwright/A11y, and production-like Docker smoke |

## Issue Ledger

| Issue | Current docs/CI/package evidence target | Residual risk until closure |
| --- | --- | --- |
| [#326](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/326) | Dependency policy, `make dependency-audit`, npm audit, PR #287 disposition | No fully pinned Python production lockfile is committed. |
| [#327](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/327) | README, `SECURITY.md`, threat model, deployment runbook, release ledger | Public-production readiness remains gated by PP5 scorecard #350. |
| [#339](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/339) | Current issue-template labels, Dependabot labels, strict evidence language | GitHub labels/milestones still require live repository review before closeout. |
| [#340](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/340) | Package policy, package-content check, `make package-check` | Future PyPI wording must keep the CLI-plus-Workbench package story explicit. |
| [#341](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/341) | Current-state roadmap docs and historical migration notes | Historical template pages must not be used as active acceptance evidence. |
| [#342](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/342) | Generated-client ownership docs and `make api-client-drift-check` | API changes still need backend/API tests owned by implementation PRs. |
| [#343](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/343) | Workbench naming in active scripts/gates and backend/app references | Storage paths with `template-*` names remain compatibility paths until a code-level migration is approved. |
| [#344](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/344) | `docs/evidence/` boundary and docs hygiene test | Large or historical artifacts must stay linked or archived, not duplicated in docs. |
| [#345](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/345) | This release evidence ledger and release checklist updates | Ledger records targets; it does not replace command output from the release candidate. |
| [#346](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/346) | `compose.production-smoke.yml`, `scripts/production_readiness_smoke.py`, and `make docker-production-smoke` | Production proof still depends on the command output from the exact release candidate. |
| [#347](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/347) | Client drift target in `release-readiness-check` | API error-envelope/auth contract assertions must remain covered by API tests. |
| [#349](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/349) | Full quality-gate command list and residual-risk section | Any exception needs owner, rationale, and a follow-up issue before closure. |
| [#350](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/350) | Final scorecard target and PP5 acceptance boundary | If any category is below target, #350 stays open with blockers. |

## Residual Risk Decision Format

## Final Scorecard Evidence Boundary

Issue [#350](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/350)
owns the final 10/10 closure decision. The scorecard must link command output
or CI artifacts for security/auth, backend/API correctness, frontend
architecture/testability, package/docs/release coherence, and production
certification. If any P1/P2 closure audit finding remains unproven, the score is
not final and the issue stays open or names the follow-up owner.

Use this format in the final PP5 issue or PR evidence comment:

```text
Category:
Evidence:
Command:
Result:
Residual risk:
Owner:
Follow-up:
Decision:
```

Accepted residual risk must have an owner and a follow-up issue unless the
reason for no follow-up is explicit in the final scorecard.
