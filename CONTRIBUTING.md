# Contributing

Thanks for contributing to `vuln-prioritizer-workbench`.

Start with the current local Workbench docs before opening broad changes:

- [README.md](README.md)
- [SUPPORT.md](SUPPORT.md)
- [MAINTAINERS.md](MAINTAINERS.md)
- [docs/current-product-state.md](docs/current-product-state.md)
- [docs/github-open-source-readiness.md](docs/github-open-source-readiness.md)
- [docs/documentation-map.md](docs/documentation-map.md)

## Scope Guardrails

- This project prioritizes known CVEs. It is not a vulnerability scanner.
- Prefer official/public sources only: NVD, FIRST EPSS, CISA KEV.
- Do not add heuristic or LLM-generated CVE-to-ATT&CK mappings.
- Keep ATT&CK optional and offline-file-based unless the project scope changes explicitly.
- Do not add exploit execution, PoC generation, credential testing, active
  probing, attack simulation, autopatching, offensive attack-chain
  instructions, or hidden live data collection.
- Keep the Workbench local-first and single-user. Do not add auth, RBAC, API
  tokens, multi-user behavior, or public-deployment hardening unless the issue
  explicitly asks for that boundary.

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
make install
```

## Local Quality Gate

GitHub Actions are intentionally not required for day-to-day development. The CI workflow mirrors the local gate below, so run all checks locally before pushing:

```bash
make local-workbench-check
```

For changes that are intended to land on `main`, prefer a pull request flow over direct pushes. The repository is maintained as a public project, so branch protection and hosted checks should act as a second line of defense after the local gate.

This runs:

- `ruff format --check`
- `ruff check`
- `mypy backend/app`
- `pytest`
- documentation hygiene and MkDocs build

## Local Workflow Equivalent

When you explicitly need the heavier maintainer workflow gate, run:

```bash
make workflow-check
```

This runs the backend quality gate, Docker base-image digest check, docs build
and evidence hygiene checks, GitHub workflow linting, pre-commit hooks, and the
Python package build/check/smoke path. It is intentionally heavier than the
ordinary PR CI gate.

Use `make clean-local` to remove ignored local caches, logs, build outputs,
coverage files, generated docs sites, and `.DS_Store` files without deleting
`.env`, local databases, `node_modules`, or Playwright browser downloads. Use
`make clean-deps` when you intentionally want to remove dependency-heavy
directories too.

## Branching And Pull Requests

- Use focused branches, normally under `codex/` for Codex-authored work.
- Prefer one roadmap issue per PR unless the dependency group is documented in
  the PR body.
- For historical migration follow-ups, keep stacked branches explicit and state
  the base branch in the PR. Do not claim removed or archived Workbench behavior
  as completion evidence for the active FastAPI/React runtime.
- Open draft PRs while evidence is still being collected.
- Keep direct pushes to `main` for emergencies only.

Pull request checklist:

- State the issue or roadmap ID, scope, and intended disposition.
- List changed surfaces: domain services, Workbench backend API, DB/migrations,
  generated client, frontend, Docker, docs, release/packaging, or security.
- Paste commands run and their results.
- Include evidence paths, screenshots, traces, API responses, migration output,
  or generated-client drift checks when relevant.
- Call out residual risk and follow-up issues.
- Avoid closing strict-DoD issues until the PR has landed and the issue has
  fresh evidence.

## Codex Working Rules

Codex-authored changes should follow the repository roadmap issue scope:

- Read the issue body and its Definition of Done before editing.
- Use the current codebase as evidence, not as an assumption that a duplicate
  roadmap item is complete.
- Do not revert unrelated user or maintainer changes.
- Do not use secrets, customer scanner data, or live-provider-only behavior as
  required CI evidence.
- Keep generated files in the same PR as the source change that produces them.
- For API changes, regenerate and check the OpenAPI client.
- For DB changes, add or update migrations and include migration/test evidence.
- For UI changes, include browser or Playwright evidence.
- For security-sensitive changes, state the boundary checked and the remaining
  deployment risk.

## Parser And Provider Extensions

New parser and provider contributions use the reviewed static extension
strategy in [docs/extension_strategy.md](docs/extension_strategy.md). Do not add
runtime plugin discovery, remote code loading, scanner execution, arbitrary
provider endpoint overrides, or live-network-only CI tests. Include sanitized
fixtures, focused tests, docs, and support-matrix updates with the contribution.

## Security Checklist

Before opening or merging a change, verify that it does not:

- add scanner, exploit, PoC, active probing, credential testing, attack
  simulation, autopatching, or heuristic ATT&CK mapping behavior
- expose tokens, API keys, cookies, private exports, or absolute local paths in
  logs, reports, screenshots, or documentation
- weaken upload limits, safe XML/file parsing, or rooted artifact paths
- add auth, RBAC, API tokens, multi-user behavior, or public-deployment
  hardening unless that boundary is explicitly in scope
- silently replace deterministic fixture tests with live-network tests

## Demo Artifacts

When output changes materially, regenerate the checked-in demo artifacts:

```bash
make demo-report
make demo-compare
make demo-explain
```

For a full release-oriented local sweep:

```bash
make release-check
```

`make release-check` remains the stricter maintainer sweep because it also regenerates the checked-in demo artifacts before packaging.

Only for an explicitly scoped release or public/shared deployment track, run the
release-readiness evidence sweep:

```bash
make release-readiness-check
```

To validate only the generated distribution artifacts and package metadata:

```bash
make package-check
```

To validate the browsable documentation site:

```bash
make docs-check
```

This gate includes stale wording checks, archive binary evidence manifest
validation, and a clean MkDocs build.

## Commit Discipline

- Keep commits focused.
- Update tests with behavioral changes.
- Update `CHANGELOG.md` for user-visible or maintainer-relevant changes when appropriate.
- Do not commit local secrets or local handoff notes.
- Prefer deterministic mocks in tests over live network calls.
- Treat direct pushes to `main` as an emergency path, not the normal maintainer workflow.
