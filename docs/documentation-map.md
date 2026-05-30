# Documentation Map

This map defines how the repository documentation is organized and how to decide
which page owns a claim. It exists to prevent the CLI, early GUI, FastAPI
template migration, Workbench release, submission, and archive eras from being
mixed together again.

## Source-Of-Truth Order

When two pages appear to conflict, use this order:

1. [Current Product State](current-product-state.md)
2. [Product Architecture](architecture.md)
3. [Contracts](contracts.md) and [Support Matrix](support_matrix.md)
4. [User Documentation Guide](user_documentation.md)
5. [GitHub Open Source Readiness](github-open-source-readiness.md) and
   [Community Repository Setup](community_repository_setup.md) for public
   repository routing and GitHub-side checklist items
6. [Release Operations](release_operations.md) and current release notes for
   package/release handoff only
7. [Historical Reference](#historical-reference) pages
8. `archive/**` evidence and historical planning material

Historical evidence can support a story, but it does not override current code,
current tests, current contracts, or current local validation evidence.

## Public Docs Inventory

| Category | Pages | Owner | Rules |
| --- | --- | --- | --- |
| Current product truth | `current-product-state.md`, `architecture.md`, `architecture/decision-evidence-kernel.md`, `documentation-map.md` | Maintainers | Must describe the active Workbench-first runtime only. |
| Evidence-backed claim routing | `documentation-evidence-matrix.md` | Maintainers | Must map major claims to code, tests, schemas, commands, archive artifacts, or external primary sources before wording is strengthened. |
| User and operator docs | `user_documentation.md`, `use_cases.md`, `demo-readiness.md`, `workbench-offline-demo.md`, `playbooks.md`, `playbooks/**` | Product/docs owner | Must favor external-user paths and mark repo-checkout-only commands. |
| Methodology | `methodology.md`, `scoring-methodology.md`, `attack-ttp-methodology.md`, `workbench-attack-methodology.md`, `benchmarking.md` | Domain owner | Must keep scoring, ATT&CK, VEX, and asset-context semantics transparent. |
| Contracts | `contracts.md`, `support_matrix.md`, `architecture/decision-evidence-kernel.md`, `asset-context-csv.md`, importer docs, examples, schemas | API/report owners | Must change with tests and generated/example artifacts when contracts change. |
| Security and deployment | `workbench-threat-model.md`, `workbench-public-deployment.md`, `release_operations.md` | Security/release owner | Must keep local/private operation as the default and treat public or shared deployment evidence as candidate-specific exception evidence. |
| Package maturity | `backend/pyproject.toml`, `README.md`, `current-product-state.md`, `dependency-and-package-policy.md`, `release_operations.md` | Release owner | Must use the same readiness level; today that level is `Development Status :: 4 - Beta` for local-first/self-hosted readiness without public/shared deployment certification. |
| Open-source repository health | `github-open-source-readiness.md`, `community_repository_setup.md`, root `CONTRIBUTING.md`, `SUPPORT.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `MAINTAINERS.md`, `CHANGELOG.md`, `.github/**` templates | Maintainers | Must route public questions, contributions, security reports, conduct issues, ownership, and GitHub-side settings without overstating what repo files configure. |
| Release history | `docs/releases/**`, `CHANGELOG.md` | Release owner | Must describe tagged or historical releases, not future state. |
| Submission package | `docs/submission/**` | Submission owner | May link archived demo proof, but must label it as demo or historical evidence. |
| Historical reference | `full_stack_fastapi_template_migration.md`, `vpw_template_execution_sequence.md`, `architecture/template-replacement.md`, `architecture/template-service-layer.md`, selected `architecture/vpw-*.md` cards | Maintainers | Must not be used as current completion evidence unless revalidated. |
| Archive pointer | `evidence.md`, `archive/README.md`, `archive/vpw-evidence/MANIFEST.md` | Evidence owner | Must point to archive contents without copying large artifacts into public docs. |

## Historical Reference

Historical reference pages explain why the repository moved from CLI-first work
through GUI experiments and into the current FastAPI/React Workbench shape. They
remain useful for migration context, but they do not certify current behavior by
themselves. Current behavior must be verified through active docs, current code,
tests, local validation evidence, and the audit trail.

## Navigation Rules

- Current pages must appear before historical pages in `mkdocs.yml`.
- Active security and deployment pages must stay in a current navigation group,
  not under Workbench History.
- Open-source repository health pages must stay discoverable from both
  `README.md` and the MkDocs navigation.
- Historical migration and template-era pages must live under a clearly labelled
  historical/reference navigation group.
- `docs/evidence/**` is limited to small contract fixtures referenced by tests
  or schemas.
- Screenshots, broad issue proof, demo screenshots, and ZIP evidence belong in
  `archive/vpw-evidence/**` or external CI artifacts.
- Tracked binary evidence under `archive/vpw-evidence/**` must be listed in
  `archive/vpw-evidence/BINARY-MANIFEST.json` and pass
  `python3 scripts/check_archive_evidence_manifest.py`.
- New Markdown files in `docs/**` must be added to `mkdocs.yml`, except the
  small non-public contract fixture allowlist enforced by
  `backend/tests/test_docs_hygiene.py`.
- Internal audits and private scorecards should stay outside `docs/**` unless
  they are intentionally published as scoped release or deployment evidence.

## Current Vs Historical Wording

Use this wording for active docs:

- "active Workbench runtime"
- "FastAPI backend under `backend/app`"
- "React/TanStack frontend under `frontend`"
- "retained domain package under `backend/src/vuln_prioritizer`"
- "historical evidence" or "demo snapshot" for archive references

Avoid this wording in active docs unless the sentence explicitly describes
compatibility or history:

- CLI-only product claims
- unqualified public/shared deployment readiness claims
- template-era evidence as closure proof
- template behavior described as current product behavior

The release evidence hygiene script checks this wording across the public docs
navigation and allows historical pages only through explicit path-based
classification.

## How To Add Or Change Docs

1. Decide the page category before writing.
2. Link to [Current Product State](current-product-state.md) if the page might
   otherwise be confused with historical material.
3. Check the [Documentation Evidence Matrix](documentation-evidence-matrix.md)
   for the evidence source that owns the claim.
4. Put current behavior, stable contracts, and historical context in separate
   sections.
5. If a page links to `archive/**`, describe whether the link is historical
   proof, demo evidence, or current release evidence.
6. Run:

```bash
python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
make docs-check
```

For behavior, API, frontend, or release-adjacent documentation changes, also run
the relevant backend, frontend, Docker, and release gates described in
[Release Operations](release_operations.md).
