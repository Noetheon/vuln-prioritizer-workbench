# Workbench v1.0 Release Checklist

Status: Workbench v1.0 milestone checklist with current package-release closeout notes.

Use this checklist before tagging or publishing a Workbench-capable package release. It is intended to collect operator evidence, not to expand product scope. The Workbench remains a local-first known-CVE prioritization tool, not a scanner, exploit framework, or heuristic ATT&CK mapper.

The Workbench v1.0 milestone evidence is preserved here, but the current package tree is versioned `1.1.0`. A tag cut from this tree must therefore be `v1.1.0`; the release workflow rejects tags that do not match `pyproject.toml`.

## Current Closeout Evidence

- Implementation baseline before this docs closeout: `f5db33f58aa14eba23daa47b38def71b243466a3`.
- GitHub tracker issues `#2`-`#79` are closed, and Workbench milestones `v0.5` through `v1.2` have zero open issues.
- Latest `main` GitHub checks for CI, CodeQL, and Docker completed successfully on `f5db33f58aa14eba23daa47b38def71b243466a3`.
- Local closeout gates recorded for the implementation baseline: `make check` (`407 passed, 2 skipped`, 90.07% coverage), `make release-check`, `make demo-evidence-bundle-check`, and `make dependency-audit`.
- The post-release docs closeout pass also passed `make docs-check`, `make demo-evidence-bundle-check`, `make dependency-audit`, `make docker-demo-smoke`, and `make release-check` on 2026-04-25.
- `python3 -m pip check` is not used as release evidence in the shared user-site environment because unrelated globally installed packages conflict with each other outside this project.
- Public package tag and GitHub Release object: `v1.1.0` published from `23199ef85fb9ac08b9bb0e301b2aadbf3377f791`.

## GitHub Tracker Mapping

- #60 `[Release] Prepare v1.0 release checklist`
- #61 `[Release] Validate clean Docker Compose quickstart`
- #62 `[Release] Update README screenshots`
- #63 `[Release] Publish demo evidence bundle`
- #64 `[Release] Prepare changelog and GitHub release notes`
- #68-#71 Advanced ATT&CK follow-up slice
- #72-#79 Integrations follow-up slice

## Release Scope

- [x] Package version, tag target, release notes, and public docs use `v1.1.0` for the package release; Workbench `v1.0.0` remains milestone evidence only.
- [x] Release scope is described as local-first CLI plus self-hosted Workbench for prioritizing known CVEs and imported findings.
- [x] SQLite-backed single-node Workbench operation is documented as the default runtime model.
- [x] Public docs identify live provider use, local cache use, and locked provider snapshot replay as distinct modes.
- [x] Workbench docs identify evidence bundles as integrity artifacts, not encrypted archives.

## Clean Compose Quickstart

- [x] Start from a clean checkout or a documented release candidate tree.
- [x] Remove stale local containers and volumes before the final Compose smoke.
- [x] Run the documented quickstart:

```bash
docker compose up --build
curl http://127.0.0.1:8000/api/health
```

- [x] Confirm `/api/health` returns an OK status from the running container.
- [x] Confirm the browser UI opens at `http://127.0.0.1:8000`.
- [x] Confirm the stack can be stopped and restarted without manual database repair.
- [x] Record the smoke-gate result, date, commit, and relevant environment notes in the release evidence.

## Demo Evidence Bundle

- [x] Run the locked-provider Workbench demo path from `docs/workbench-offline-demo.md`.
- [x] Generate and verify the CLI evidence bundle:

```bash
make demo-evidence-bundle-check
```

- [x] Import the documented fixture input with the locked provider snapshot enabled.
- [x] Generate JSON, Markdown, HTML, CSV where supported, and Evidence ZIP artifacts.
- [x] Verify the Evidence ZIP using the Workbench verification path or documented verification command.
- [x] Attach or archive `build/v1.0-demo-analysis.json`, `build/v1.0-demo-evidence-bundle.zip`, and `build/v1.0-demo-evidence-bundle-verification.json` with the release evidence.
- [x] Save the evidence manifest, verification report, generated reports, and relevant command output together.
- [x] Confirm evidence artifacts show provider provenance, run metadata, source input format, and hashes where applicable.
- [x] Confirm `build/v1.0-demo-evidence-bundle-verification.json` records `summary.ok=true`, `missing_files=0`, `modified_files=0`, `unexpected_files=0`, and `manifest_errors=0`.
- [x] Record `git rev-parse HEAD`, the run date, and SHA-256 values for the three generated `build/v1.0-demo-*` artifacts:

```bash
shasum -a 256 \
  build/v1.0-demo-analysis.json \
  build/v1.0-demo-evidence-bundle.zip \
  build/v1.0-demo-evidence-bundle-verification.json
```

- [x] Confirm evidence artifacts do not include secrets, raw environment values, API keys, cookies, or private shell history.
- [x] Keep archived paths repository-relative; do not record private absolute paths from a maintainer workstation.

## Screenshot Set

Capture screenshots from the same release candidate that produced the evidence bundle:

- [x] Project setup or dashboard entry point.
- [x] Import form with locked provider snapshot selected.
- [x] Dashboard with priority counts and provider freshness visible.
- [x] Findings table with filters applied.
- [x] Finding detail page showing priority rationale, CVSS, EPSS, KEV, component, asset, owner, and raw evidence.
- [x] Vulnerability Intelligence or equivalent lookup page showing stored provider data.
- [x] Settings or runtime status page showing secret redaction.
- [x] Reports page showing generated JSON, Markdown, HTML, and Evidence ZIP artifacts.
- [x] Evidence ZIP verification result.
- [x] README media links point to the current checked-in Workbench screenshots:
  `docs/examples/media/workbench-dashboard.png`,
  `docs/examples/media/workbench-findings.png`,
  `docs/examples/media/workbench-finding-detail-ttp.png`, and
  `docs/examples/media/workbench-reports-evidence.png`.

Sanitization requirements:

- [x] Capture from the locked offline demo path, not customer scanner exports or live provider-only data.
- [x] Crop to the Workbench/report UI and avoid shell history, private browser profiles, local home-directory paths, and unrelated desktop content.
- [x] Confirm settings and runtime pages show secrets only as `<set>` or `<not set>`.
- [x] If README media links are refreshed, keep paths repository-relative and commit binary replacements only when the release owner explicitly approves them.

## Dependency Audit

- [x] Run the dependency audit against the repository dependency file:

```bash
make dependency-audit
```

- [x] Record the exact command output in the release evidence folder.
- [x] If `pip-audit` or advisory data is unavailable, record the failure as a release exception with date, environment, and retry decision.
- [x] Review any reported advisories and record the disposition: fixed, accepted with rationale, not applicable, or blocked release.
- [x] Confirm no dependency-audit exception is hidden from release notes.

## Workflow and Release Gates

- [x] Run the local release gate:

```bash
make release-check
```

- [x] Run the documentation gate:

```bash
make docs-check
```

- [x] Run the Workbench smoke gate when Docker is available:

```bash
make docker-demo-smoke
```

- [x] Run `make workflow-check` before merge or tagging when Docker and pre-commit tooling are available.
- [x] Run `make demo-sync-check-temp` before tagging when examples or report outputs changed.
- [x] Confirm release workflow configuration still builds distributions, validates them, creates the GitHub Release from checked-in notes, and only publishes to PyPI when the repository gate allows it.
- [x] Confirm the tagged release notes file exists under `docs/releases/`.
- [x] Confirm GitHub Release, tag, package metadata, and docs version all match.

## Changelog and Release Notes

- [x] Create or update `docs/releases/workbench-v1.0.0.md`.
- [x] Include the Workbench scope, supported inputs, supported report and evidence outputs, and known local-first deployment assumptions.
- [x] Link the v1.0 checklist evidence location or summarize the recorded gates.
- [x] Document dependency-audit results and accepted exceptions.
- [x] Document any demo limitations, unavailable providers, or deferred Workbench hardening items.
- [x] Confirm README and documentation quickstarts do not promise unsupported scanner, exploit, SaaS, multi-tenant, or heuristic ATT&CK features.

## Product Guardrails

The v1.0 release must keep these boundaries visible in docs, UI copy, examples, and release notes:

- [x] No scanner: the project prioritizes known CVEs and imported scanner/SBOM findings; it does not discover vulnerabilities by scanning hosts, networks, containers, source code, or cloud accounts.
- [x] No exploit tooling: docs and demos do not include payloads, proof-of-concept exploit steps, exploit verification, or instructions for offensive validation.
- [x] No heuristic ATT&CK mapping: ATT&CK context comes from documented local CTID JSON mappings and metadata; absent CVEs remain unmapped unless a supported source maps them.
- [x] No hidden AI or fuzzy mapping: release copy does not imply generated CVE-to-ATT&CK guesses.
- [x] No ATT&CK-as-proof wording: ATT&CK context is described as defensive context, not evidence that exploitation occurred.
- [x] Base priority remains explainable from CVSS, EPSS, and KEV, with ATT&CK, asset context, VEX, and waivers shown as separate context or applicability layers.

## Residual Risks to State

- [x] The Workbench is local-first and is not hardened for public internet exposure.
- [x] SSO, multi-user isolation, audit logging, and ticket sync remain outside the v1.0 local Workbench scope unless explicitly shipped; the later local API-token gate is documented as a v1.2 automation control, not a full internet-facing auth model.
- [x] SQLite backup, retention, filesystem permissions, and local disk protection remain operator responsibilities.
- [x] Evidence bundles provide integrity checks but not encryption.
- [x] Imported scanner exports may contain sensitive hostnames, package paths, image names, services, owners, and environment labels.
- [x] Live provider availability and advisory feeds may fail or be rate-limited; locked snapshots are the reproducible demo path.
- [x] ATT&CK data may be incomplete or drift from upstream sources; unmapped CVEs must remain explicit rather than guessed.

## Sign-Off Record

| Area | Evidence path or note | Owner | Date |
| --- | --- | --- | --- |
| Compose quickstart | `make docker-demo-smoke`; GitHub Docker workflow green on `main` | Codex technical validation | 2026-04-25 |
| Screenshot set | `docs/examples/media/workbench-*.png` | Codex technical validation | 2026-04-25 |
| Evidence bundle verification | `make demo-evidence-bundle-check`; hashes recorded in Workbench and v1.1 release notes | Codex technical validation | 2026-04-25 |
| Dependency audit | `make dependency-audit`; no known vulnerabilities reported for `requirements.txt` | Codex technical validation | 2026-04-25 |
| Release gates | `make release-check`; GitHub CI/CodeQL/Docker green on `main` | Codex technical validation | 2026-04-25 |
| Changelog and release notes | `CHANGELOG.md`, `docs/releases/workbench-v1.0.0.md`, `docs/releases/v1.1.0.md` | Codex technical validation | 2026-04-25 |
| Product guardrails review | Docs preserve no-scanner, no-exploit, no-heuristic-ATT&CK boundaries | Codex technical validation | 2026-04-25 |
| Residual risks accepted | Residual risks documented for the published local-first package release; separate public-internet deployment acceptance remains out of release scope | Codex technical validation | 2026-04-25 |
