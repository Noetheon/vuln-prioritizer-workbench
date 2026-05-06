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

## Release Candidate Ledger

Every release candidate entry must include the exact command, commit or tag,
result, artifact path or CI URL, residual risk, owner, and follow-up. Public
entries may link CI artifacts or checked-in public-safe evidence. They must not
paste secrets, tokens, cookies, customer exports, private absolute paths, or
shell history.

| Candidate | Commit/Tag | Command | Result | Artifact or CI URL | Residual risk | Owner | Follow-up |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PP6 dry-run gate design | working tree before next tag | `python3 scripts/check_release_evidence_hygiene.py`; `make docs-check`; tag workflow runs `make release-readiness-check` | Local hygiene check and docs build required before handoff; full production-like smoke evidence is produced by the tag workflow before publishing. | `docs/evidence/vpw-052-positive-verification.json`; `release-readiness-evidence` workflow artifact on tag runs | Tag-specific Docker logs and artifact hashes exist only after the release workflow runs for the exact candidate. | Release owner | [#382](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/382), [#385](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/385), [#386](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/386) |

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
| [#380](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/380) | CI frontend PR gate runs lint, build, unit tests, generated-client drift, and bounded Playwright smoke/responsive/accessibility specs for frontend/API/runtime changes. | Fresh workflow evidence is still required for docs-only, frontend-only, and API-client-impacting PR examples. |
| [#381](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/381) | Docker PR gate runs `make docker-demo-smoke` for runtime inputs and prints compose status/logs on failure. | Fresh workflow evidence is still required for backend/Compose and docs-only PR examples. |
| [#382](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/382) | Tag release workflow runs `make release-readiness-check`, uploads release-readiness evidence, and attaches SHA-256 artifact hashes to GitHub Releases. | A tag-specific workflow run is required before claiming candidate evidence. |
| [#383](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/383) | `backend/requirements.txt` is the authoritative bounded Python audit input; `scripts/check_release_evidence_hygiene.py` fails drift against `backend/pyproject.toml`; `make dependency-audit` audits that source. | No separate fully pinned Python production lockfile exists unless a future issue intentionally adds one. |
| [#384](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/384) | `make docs-check` runs the release-evidence hygiene script before MkDocs to catch stale public-production, CLI-only, and historical-template closure wording in active release docs. | The script is intentionally narrow; broader wording cleanup still needs human review during release evidence comments. |
| [#385](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/385) | This ledger now requires commit/tag, command, result, artifact or CI URL, residual risk, owner, and follow-up fields for candidate evidence. | Build-local artifacts under `build/` are checked only when present in generated release workflow evidence. |
| [#386](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/386) | PR template and release operations docs require release-readiness ownership, skip rationale, non-readiness wording, and required-context documentation. | Branch protection itself must be confirmed in GitHub repository settings by a maintainer. |
| [#387](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/387) | Live issue list evidence captured on 2026-05-06 shows PP6 issues #379-#387 assigned to milestone `PP6 CI/Release Evidence Hardening` with `status:strict-dod`. | Labels and milestones can change after this ledger entry; closeout still needs fresh `gh issue list` output. |

## PP6 Milestone Hygiene Snapshot

Captured on 2026-05-06 with:

```bash
gh issue list --milestone "PP6 CI/Release Evidence Hardening" \
  --json number,title,labels,milestone,state --limit 100
```

| Issue | State | Required hygiene observed |
| --- | --- | --- |
| #379 | Open | milestone assigned; `type:epic`; `area:ci`; `type:release`; `status:strict-dod` |
| #380 | Open | milestone assigned; frontend/UI/CI labels; `priority:p0`; `status:strict-dod` |
| #381 | Open | milestone assigned; backend/frontend/CI labels; `priority:p0`; `status:strict-dod` |
| #382 | Open | milestone assigned; release/security/CI labels; `priority:p0`; `status:strict-dod` |
| #383 | Open | milestone assigned; dependency/python/security labels; `priority:p1`; `status:strict-dod` |
| #384 | Open | milestone assigned; docs/data-quality labels; `priority:p1`; `status:strict-dod` |
| #385 | Open | milestone assigned; docs/release/report labels; `priority:p1`; `status:strict-dod` |
| #386 | Open | milestone assigned; release/docs/CI labels; `priority:p0`; `status:strict-dod` |
| #387 | Open | milestone assigned; CI task labels; `priority:p1`; `status:strict-dod` |

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
