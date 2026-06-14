# Public-Production Release Evidence Ledger

This ledger tracks public or shared deployment evidence without turning one
audit closeout into a blanket certification. It is a public-safe index for
commands, generated artifacts, package boundaries, and residual risks.
Historical PP5/PP6 rows are retained for provenance only; they do not replace
fresh evidence for a current release or deployment candidate.

## Acceptance Boundary

The historical
[VPW-AUD-999 final scorecard](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/430)
closed on 2026-05-08. Historical scorecards such as
[#350](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/350) are
background evidence only. This document remains a readiness ledger and
release-target checklist, not a standing certification for future public
deployments.

Evidence added to public docs must avoid secrets, tokens, cookies, customer
exports, private absolute paths, and shell history. Current contract artifacts
belong in `docs/evidence/`; screenshots, historical issue proof, and broader
validation logs belong under `archive/vpw-evidence/` or external CI artifacts
linked from an issue or PR.

## Selected Package and Runtime Story

- The active browser Workbench runtime is `backend/app`.
- The Python distribution intentionally ships both `backend/app/**` and
  `backend/app/domain/engine/**`.
- The current package maturity classifier is `Development Status :: 4 - Beta`.
  This means local-first self-hosted Workbench readiness, with shared domain
  code in the package; it is not a public-production certification.
- The frontend generated OpenAPI client is `frontend/src/client/**`.
- `frontend/src/api-client.ts` is a manual wrapper over the generated client,
  not generated output.
- `uv.lock` is the reproducible Python resolution artifact.
- `backend/requirements.lock.txt` is the hash-pinned Python audit input exported
  from `uv.lock`.
- `backend/requirements.runtime.lock.txt` is the hash-pinned Python 3.13 Docker
  runtime install input exported from `uv.lock` without dev extras.
- `frontend/package-lock.json` is the audited frontend lockfile.
- There is no tracked root `bun.lock`; npm and `frontend/package-lock.json`
  remain the frontend release audit source.

## Release-Readiness Targets

| Target | Purpose | Evidence |
| --- | --- | --- |
| `make dependency-audit` | Backend and frontend dependency audit | Python lock hygiene for audit and Docker runtime locks plus `pip-audit` on `backend/requirements.lock.txt`; npm audit on `frontend/package-lock.json` |
| `make package-check` | Build, package-content, and metadata validation | `dist/*`, `twine check`, `build/package-contents.json`; package contents must include every tracked Workbench Alembic migration |
| `make api-client-drift-check` | OpenAPI/generated-client compatibility | `scripts/generate-client.sh`; clean `frontend/src/client` diff |
| `make docs-check` | Public documentation build | clean MkDocs build |
| `python3 scripts/check_public_deployment_evidence.py` | Public TLS and Traefik evidence contract | Static validation that Compose Traefik labels, production-smoke topology, and deployment docs cover same-origin routing, optional direct API routing, TLS, dashboard controls, and header evidence |
| `python3 scripts/check_archive_evidence_manifest.py` | Archive binary evidence manifest | Hash/size/purpose validation for tracked historical binary evidence and ZIP member safety checks |
| Workbench evidence bundle verification | Evidence bundle integrity | `build/v1.0-demo-evidence-bundle-verification.json` or current report verification output |
| `make docker-demo-smoke` | Compose runtime smoke | backend/frontend health, Postgres Alembic/schema/repository smoke, plus import/provider smoke |
| `make docker-production-smoke` | Production-like same-origin smoke | production env, non-default secrets, Postgres Alembic/schema/repository smoke, CSP, health/status split, import, and report download |
| `make playwright-check` | Browser smoke and accessibility path | frontend Playwright smoke, responsive shell, and Axe no serious/critical violations |
| `make release-readiness-check` | Full local readiness handoff | release gate, client drift, archive binary evidence manifest, evidence bundle, Playwright/A11y, and production-like Docker smoke. Public/shared deployment evidence remains an explicit extra check for candidates that need it. |

## Candidate Fresh Evidence Gate

Current launch or deployment claims cannot rely on historical PP evidence,
local ignored artifacts, or a previous candidate run. The current release or
deployment decision must link public-safe command output, CI artifacts, or
issue evidence produced for the exact commit, tag, or release candidate being
scored.

Required before public or shared deployment readiness is claimed for a
candidate:

- category scorecards are closed for Backend/API (#403), Frontend/UI (#411),
  Security/Deployment (#417), Docs (#422), CI/Release (#425), and Repo Hygiene
  (#429)
- `make check`
- frontend lint, build, and unit-test evidence, either through
  `make frontend-check` or explicit `make frontend-lint`, `make frontend-build`,
  and `make frontend-test-unit` output
- `make playwright-check`
- `make docs-check`
- `python3 scripts/check_public_deployment_evidence.py`
- `python3 scripts/check_archive_evidence_manifest.py`
- `make dependency-audit`
- `make docker-demo-smoke`
- `make docker-production-smoke`
- `make api-client-drift-check`
- `make package-check`
- `make release-readiness-check`
- final residual-risk decisions that name an owner and follow-up issue, or
  state why no follow-up is required

Evidence must not include secrets, token values, cookies, customer exports,
private absolute paths, or shell history. When using workflow artifacts, link
the run URL and artifact name rather than pasting raw logs into public docs.

Public TLS and Traefik evidence must include the commands from the
[Public TLS Evidence Checklist](./workbench-public-deployment.md#public-tls-evidence-checklist),
including header captures for the frontend, same-origin health route, and
reviewed direct API route. The archive binary evidence manifest must match
`archive/vpw-evidence/BINARY-MANIFEST.json`; update the manifest only when the
new binary evidence is public-safe and purpose-labelled.

## Release Candidate Ledger

Every release candidate entry must include the exact command, commit or tag,
result, artifact path or CI URL, residual risk, owner, and follow-up. Public
entries may link CI artifacts or checked-in public-safe evidence. They must not
paste secrets, tokens, cookies, customer exports, private absolute paths, or
shell history.

| Candidate | Commit/Tag | Command | Result | Artifact or CI URL | Residual risk | Owner | Follow-up |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Historical PP6 dry-run gate design | working tree before the next tag at the time of the PP6 work | `python3 scripts/check_release_evidence_hygiene.py`; `make docs-check`; tag workflow runs `make release-readiness-check` | Historical local hygiene and docs-build design evidence. Current release readiness still requires fresh evidence for the exact candidate. | `docs/evidence/vpw-052-positive-verification.json`; historical `release-readiness-evidence` workflow artifacts on tag runs | Tag-specific Docker logs and artifact hashes exist only after the release workflow runs for the exact candidate. Historical PP6 evidence is not a current release certification. | Release owner | Historical references: [#382](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/382), [#385](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/385), [#386](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/386), and the closed VPW-AUD-999 final scorecard [#430](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/430). |

## Historical Issue Ledger

The rows below preserve why prior PP evidence exists. They are not live issue
status, and they do not satisfy the current VPW-AUD scorecards by themselves.
Use live GitHub issue state plus VPW-AUD closeout comments for current closure
decisions.

| Issue | Current docs/CI/package evidence target | Residual risk until closure |
| --- | --- | --- |
| [#326](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/326) | Dependency policy, `uv.lock`, `backend/requirements.lock.txt`, `make dependency-audit`, npm audit, PR #287 disposition | Release owners still need candidate-specific audit output and artifact hashes before closeout. |
| [#327](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/327) | README, `SECURITY.md`, threat model, deployment runbook, release ledger | Historical public-production wording; current readiness is candidate-specific and cannot be inherited from prior scorecards. |
| [#339](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/339) | Current issue-template labels, Dependabot labels, strict evidence language | GitHub labels/milestones still require live repository review before closeout. |
| [#340](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/340) | Package policy, package-content check, `make package-check` | Future PyPI wording must keep the Workbench-first package story explicit and avoid re-advertising the retired CLI as a product surface. |
| [#341](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/341) | Current-state roadmap docs and historical migration notes | Historical template pages must not be used as active acceptance evidence. |
| [#342](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/342) | Generated-client ownership docs and `make api-client-drift-check` | API changes still need backend/API tests owned by implementation PRs. |
| [#343](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/343) | Active runtime state keys, API operation IDs, provider update metadata, import-stage helper names, and default artifact paths use Workbench naming. | A small app-state compatibility alias and legacy Docker volume-name defaults remain so existing self-hosted data is not orphaned. |
| [#344](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/344) | `docs/evidence/` boundary and docs hygiene test | Large or historical artifacts must stay linked or archived, not duplicated in docs. |
| [#345](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/345) | This release evidence ledger and release checklist updates | Ledger records targets; it does not replace command output from the release candidate. |
| [#346](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/346) | `compose.production-smoke.yml`, `scripts/production_readiness_smoke.py`, and `make docker-production-smoke` | Production proof still depends on the command output from the exact release candidate. |
| [#347](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/347) | Client drift target in `release-readiness-check` | API error-envelope and local runtime access assertions must remain covered by API tests. |
| [#349](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/349) | Full quality-gate command list and residual-risk section | Any exception needs owner, rationale, and a follow-up issue before closure. |
| [#350](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/350) | Historical final scorecard target and PP5 acceptance boundary | Historical scorecard evidence; current public deployment claims still need fresh candidate evidence. |
| [#380](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/380) | CI frontend PR gate runs lint, build, unit coverage, generated-client drift, scoped Playwright coverage, and full browser/visual coverage for UI/browser-risk changes. | Fresh workflow evidence is still required for docs-only, frontend-only, and API-client-impacting PR examples. |
| [#381](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/381) | Docker PR gate runs `make docker-demo-smoke` and `make docker-production-smoke` for runtime inputs and prints compose status/logs on failure. | Fresh workflow evidence is still required for backend/Compose and docs-only PR examples. |
| [#382](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/382) | Tag release workflow runs `make release-readiness-check`, uploads release-readiness evidence, and attaches SHA-256 artifact hashes to GitHub Releases. | A tag-specific workflow run is required before claiming candidate evidence. |
| [#383](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/383) | `backend/requirements.txt` is the bounded Python policy input; `uv.lock` records the resolver state; `backend/requirements.lock.txt` is exported with pins and hashes for dependency audit; `backend/requirements.runtime.lock.txt` is exported separately for the Python 3.13 Docker runtime install. | Fresh lock refresh and audit output are still required for each exact release candidate. |
| [#384](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/384) | `make docs-check` runs the release-evidence hygiene script and archive manifest check before MkDocs to catch stale release wording and tracked artifact drift in active docs. | Public-deployment evidence remains an explicit release-readiness/public-deployment check, not a default docs-build requirement. |
| [#385](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/385) | This ledger now requires commit/tag, command, result, artifact or CI URL, residual risk, owner, and follow-up fields for candidate evidence. | Build-local artifacts under `build/` are checked only when present in generated release workflow evidence. |
| [#386](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/386) | PR template scopes release-readiness validation to explicit release, public/shared deployment, or release-evidence work instead of ordinary local Workbench PRs. | Branch protection itself must be confirmed in GitHub repository settings by a maintainer. |
| [#387](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/387) | Historical issue list evidence captured on 2026-05-06 shows PP6 issues #379-#387 assigned to milestone `PP6 CI/Release Evidence Hardening` with `status:strict-dod` at capture time. | Labels, milestones, and states can change after this ledger entry; current closeout must use fresh `gh issue list` or VPW-AUD evidence output. |

## Historical PP6 Milestone Hygiene Snapshot

This snapshot records the PP6 issue hygiene observed on 2026-05-06. It is not a
live issue-state table. A fresh `--state all` check during VPW-AUD-404 showed
#379-#387 closed, so the table below remains historical evidence rather than a
current blocker list.

Captured on 2026-05-06 with:

```bash
gh issue list --milestone "PP6 CI/Release Evidence Hardening" \
  --json number,title,labels,milestone,state --limit 100
```

| Issue | State on 2026-05-06 | Required hygiene observed |
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

Issue [#430](https://github.com/Noetheon/vuln-prioritizer-workbench/issues/430)
closed the historical final 10/10 audit scorecard on 2026-05-08. That scorecard
does not replace current candidate evidence for security/auth, backend/API
correctness, frontend architecture/testability, package/docs/release coherence,
and production deployment decisions. If any P1/P2 release-candidate audit
finding remains unproven, the current candidate must name the follow-up owner
and avoid public-readiness wording.

Use this format in the VPW-AUD-999 issue or PR evidence comment:

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
