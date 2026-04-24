# Workbench v1.0 Release Checklist

Status: docs-only release checklist for the Workbench v1.0 readiness gate.

Use this checklist before tagging or publishing the Workbench v1.0 release. It is intended to collect operator evidence, not to expand product scope. The Workbench remains a local-first known-CVE prioritization tool, not a scanner, exploit framework, or heuristic ATT&CK mapper.

## GitHub Tracker Mapping

- #60 `[Release] Prepare v1.0 release checklist`
- #61 `[Release] Validate clean Docker Compose quickstart`
- #62 `[Release] Update README screenshots`
- #63 `[Release] Publish demo evidence bundle`
- #64 `[Release] Prepare changelog and GitHub release notes`

## Release Scope

- [ ] Version, tag, release notes, and public docs all use the same Workbench `v1.0.0` release identifier.
- [ ] Release scope is described as local-first CLI plus self-hosted Workbench for prioritizing known CVEs and imported findings.
- [ ] SQLite-backed single-node Workbench operation is documented as the default runtime model.
- [ ] Public docs identify live provider use, local cache use, and locked provider snapshot replay as distinct modes.
- [ ] Workbench docs identify evidence bundles as integrity artifacts, not encrypted archives.

## Clean Compose Quickstart

- [ ] Start from a clean checkout or a documented release candidate tree.
- [ ] Remove stale local containers and volumes before the final Compose smoke.
- [ ] Run the documented quickstart:

```bash
docker compose up --build
curl http://127.0.0.1:8000/api/health
```

- [ ] Confirm `/api/health` returns an OK status from the running container.
- [ ] Confirm the browser UI opens at `http://127.0.0.1:8000`.
- [ ] Confirm the stack can be stopped and restarted without manual database repair.
- [ ] Record the command output, date, commit, Docker version, and operating system in the release evidence folder.

## Demo Evidence Bundle

- [ ] Run the locked-provider Workbench demo path from `docs/workbench-offline-demo.md`.
- [ ] Generate and verify the CLI evidence bundle:

```bash
make demo-evidence-bundle-check
```

- [ ] Import the documented fixture input with the locked provider snapshot enabled.
- [ ] Generate JSON, Markdown, HTML, CSV where supported, and Evidence ZIP artifacts.
- [ ] Verify the Evidence ZIP using the Workbench verification path or documented verification command.
- [ ] Attach or archive `build/v1.0-demo-analysis.json`, `build/v1.0-demo-evidence-bundle.zip`, and `build/v1.0-demo-evidence-bundle-verification.json` with the release evidence.
- [ ] Save the evidence manifest, verification report, generated reports, and relevant command output together.
- [ ] Confirm evidence artifacts show provider provenance, run metadata, source input format, and hashes where applicable.
- [ ] Confirm evidence artifacts do not include secrets, raw environment values, API keys, cookies, or private shell history.

## Screenshot Set

Capture screenshots from the same release candidate that produced the evidence bundle:

- [ ] Project setup or dashboard entry point.
- [ ] Import form with locked provider snapshot selected.
- [ ] Dashboard with priority counts and provider freshness visible.
- [ ] Findings table with filters applied.
- [ ] Finding detail page showing priority rationale, CVSS, EPSS, KEV, component, asset, owner, and raw evidence.
- [ ] Vulnerability Intelligence or equivalent lookup page showing stored provider data.
- [ ] Settings or runtime status page showing secret redaction.
- [ ] Reports page showing generated JSON, Markdown, HTML, and Evidence ZIP artifacts.
- [ ] Evidence ZIP verification result.

## Dependency Audit

- [ ] Run the dependency audit against the repository dependency file:

```bash
make dependency-audit
```

- [ ] Record the exact command output in the release evidence folder.
- [ ] If `pip-audit` or advisory data is unavailable, record the failure as a release exception with date, environment, and retry decision.
- [ ] Review any reported advisories and record the disposition: fixed, accepted with rationale, not applicable, or blocked release.
- [ ] Confirm no dependency-audit exception is hidden from release notes.

## Workflow and Release Gates

- [ ] Run the local release gate:

```bash
make release-check
```

- [ ] Run the documentation gate:

```bash
make docs-check
```

- [ ] Run the Workbench smoke gate when Docker is available:

```bash
make docker-demo-smoke
```

- [ ] Run `make workflow-check` before merge or tagging when Docker and pre-commit tooling are available.
- [ ] Run `make demo-sync-check-temp` before tagging when examples or report outputs changed.
- [ ] Confirm release workflow configuration still builds distributions, validates them, creates the GitHub Release from checked-in notes, and only publishes to PyPI when the repository gate allows it.
- [ ] Confirm the tagged release notes file exists under `docs/releases/`.
- [ ] Confirm GitHub Release, tag, package metadata, and docs version all match.

## Changelog and Release Notes

- [ ] Create or update `docs/releases/workbench-v1.0.0.md`.
- [ ] Include the Workbench scope, supported inputs, supported report and evidence outputs, and known local-first deployment assumptions.
- [ ] Link the v1.0 checklist evidence location or summarize the recorded gates.
- [ ] Document dependency-audit results and accepted exceptions.
- [ ] Document any demo limitations, unavailable providers, or deferred Workbench hardening items.
- [ ] Confirm README and documentation quickstarts do not promise unsupported scanner, exploit, SaaS, multi-tenant, or heuristic ATT&CK features.

## Product Guardrails

The v1.0 release must keep these boundaries visible in docs, UI copy, examples, and release notes:

- [ ] No scanner: the project prioritizes known CVEs and imported scanner/SBOM findings; it does not discover vulnerabilities by scanning hosts, networks, containers, source code, or cloud accounts.
- [ ] No exploit tooling: docs and demos do not include payloads, proof-of-concept exploit steps, exploit verification, or instructions for offensive validation.
- [ ] No heuristic ATT&CK mapping: ATT&CK context comes from documented local CTID JSON mappings and metadata; absent CVEs remain unmapped unless a supported source maps them.
- [ ] No hidden AI or fuzzy mapping: release copy does not imply generated CVE-to-ATT&CK guesses.
- [ ] No ATT&CK-as-proof wording: ATT&CK context is described as defensive context, not evidence that exploitation occurred.
- [ ] Base priority remains explainable from CVSS, EPSS, and KEV, with ATT&CK, asset context, VEX, and waivers shown as separate context or applicability layers.

## Residual Risks to State

- [ ] The Workbench is local-first and is not hardened for public internet exposure.
- [ ] Authentication, authorization, SSO, API tokens, multi-user isolation, audit logging, and ticket sync remain outside the v1.0 local Workbench scope unless explicitly shipped.
- [ ] SQLite backup, retention, filesystem permissions, and local disk protection remain operator responsibilities.
- [ ] Evidence bundles provide integrity checks but not encryption.
- [ ] Imported scanner exports may contain sensitive hostnames, package paths, image names, services, owners, and environment labels.
- [ ] Live provider availability and advisory feeds may fail or be rate-limited; locked snapshots are the reproducible demo path.
- [ ] ATT&CK data may be incomplete or drift from upstream sources; unmapped CVEs must remain explicit rather than guessed.

## Sign-Off Record

| Area | Evidence path or note | Owner | Date |
| --- | --- | --- | --- |
| Compose quickstart |  |  |  |
| Screenshot set |  |  |  |
| Evidence bundle verification |  |  |  |
| Dependency audit |  |  |  |
| Release gates |  |  |  |
| Changelog and release notes |  |  |  |
| Product guardrails review |  |  |  |
| Residual risks accepted |  |  |  |
