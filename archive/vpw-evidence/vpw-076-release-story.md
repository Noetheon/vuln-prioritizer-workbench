# VPW-076 Release Story Evidence

VPW-076 closes the duplicated release-hardening roadmap item for v1.0 release notes, changelog evidence, demo evidence bundle verification, screenshots, and an exam-ready story. It does not add product scope. It collects and verifies the already shipped Workbench v1.0/v1.1 release artifacts into one strict-DoD evidence package.

Status: historical issue-level evidence. The commands and paths below describe
the then-active release-story closeout and must not be reused as current release
or deployment proof without fresh validation.

## Release Artifact Map

| Requirement | Evidence |
| --- | --- |
| Changelog | `CHANGELOG.md` documents the Workbench-capable `1.1.0` package line and preserves `1.0.0` as the stable OSS release line. |
| Release notes | `docs/releases/workbench-v1.0.0.md` explicitly documents Features, Non-Goals, Known Limitations, demo evidence, and bundle verification expectations. `docs/releases/v1.1.0.md` documents the package tag that carries the current Workbench tree. |
| Release checklist | `docs/workbench-v1-release-checklist.md` records the v1.0 milestone checklist, gate expectations, screenshot set, residual risks, and sign-off table. |
| Demo evidence bundle | Historical target `make demo-evidence-bundle-check` generated and verified `build/v1.0-demo-evidence-bundle.zip`; the durable verification output now lives at `archive/vpw-evidence/vpw-076-demo-evidence-bundle-verification.json`. |
| Screenshots | `docs/examples/media/workbench-dashboard.png`, `docs/examples/media/workbench-findings.png`, `docs/examples/media/workbench-finding-detail-ttp.png`, `docs/examples/media/workbench-reports-evidence.png`, plus VPW-075 evidence screenshots. |
| Roadmap v1.1/v1.2 | `docs/roadmap.md` records the implemented `v1.1.0` release surface and current Workbench app direction through the integration slices. |
| Backup plan | See "Demo Backup Plan" below. |

## Verification Run

Run date: 2026-04-30

Commands:

```bash
make demo-evidence-bundle-check
shasum -a 256 \
  build/v1.0-demo-analysis.json \
  build/v1.0-demo-evidence-bundle.zip \
  build/v1.0-demo-evidence-bundle-verification.json
make docs-check
```

Verification summary from `build/v1.0-demo-evidence-bundle-verification.json`:

```json
{
  "summary": {
    "expected_files": 6,
    "manifest_errors": 0,
    "missing_files": 0,
    "modified_files": 0,
    "ok": true,
    "total_members": 7,
    "unexpected_files": 0,
    "verified_files": 6
  },
  "metadata": {
    "bundle_kind": "evidence-bundle",
    "bundle_path": "build/v1.0-demo-evidence-bundle.zip",
    "generated_at": "2026-04-21T12:00:00+00:00",
    "manifest_schema_version": "1.1.0",
    "schema_version": "1.2.0"
  }
}
```

Current artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `build/v1.0-demo-analysis.json` | `9264e7cf94fdd4e343ce6a991476f89cb71b5f9e0f8185d87ea73684610587b0` |
| `build/v1.0-demo-evidence-bundle.zip` | `f478f0334964defba2cf815c4f09037a99743a80528f7a41db0e05b5a21fbce5` |
| `build/v1.0-demo-evidence-bundle-verification.json` | `da6791865a2c70116d9d00c2ebf21d4a9a7fdfeb6de8ad8c52d7060614b7a854` |

The same verification output is archived in
`archive/vpw-evidence/vpw-076-demo-evidence-bundle-verification.json` so the
issue and PR retain durable historical evidence even though `build/` remains
ignored.

## 15-Minute Demo Story

### Technical flow, 7 minutes

1. Start from the local-first boundary: the Workbench prioritizes known CVEs from imported files; it does not scan or exploit targets.
2. Open the Docker quickstart evidence and show the local backend/frontend entry points.
3. Import the locked demo input with provider snapshot replay enabled so feed drift does not affect the story.
4. Show the technical finding path: input source, CVE, component, CVSS, EPSS, KEV, data-quality flags, ATT&CK context, asset context, and VEX applicability.
5. Generate reports and the evidence bundle, then verify the bundle manifest and hashes.
6. Point to the release checks: `make check`, Docker smoke, dependency audit, docs check, and demo evidence verification.

### CISO flow, 7 minutes

1. Start with the dashboard and priority counts, emphasizing that priority is explainable from CVSS, EPSS, and KEV.
2. Show the same finding as business risk: threat signal, impacted service/owner, exposure context, accepted risk status, and recommended action.
3. Use the reports page to show executive HTML/Markdown and evidence ZIP outputs.
4. Explain governance: waivers do not hide findings, VEX statuses are visible, and missing asset context remains explicit unknown context.
5. Close with release boundaries: local-first, single-node, no public-internet hardening promise, no scanner, no exploit tooling, no heuristic ATT&CK mapping.

The remaining minute is reserved for questions or for switching to the backup path if a live browser flow is unavailable.

### Required review path

| Step | Demo point |
| --- | --- |
| Technical Finding | The locked Trivy import surfaces a concrete CVE occurrence with package/version, CVSS, EPSS, KEV, data-quality flags, ATT&CK context, asset context, and VEX status. |
| Threat | KEV, EPSS, and source-backed ATT&CK context explain the exploitation and adversary-technique signal without inventing mappings. |
| Asset | Asset context links the occurrence to service, owner, environment, exposure, and criticality so the finding is not just a package row. |
| Business Impact | The CISO path translates the same finding into service risk, accepted or suppressed status, unknown context, and reporting evidence. |
| Measure | Recommended action, governance state, waivers/VEX visibility, and report/evidence exports show the mitigation or decision path. |
| Priority | Final priority remains explainable from CVSS, EPSS, and KEV, with contextual fields visible as evidence instead of hidden scoring changes. |

## Demo Backup Plan

If Docker, browser automation, or local ports are unavailable during the review:

1. Use the checked-in release notes and this evidence document as the narrative source.
2. Show the static screenshots in `docs/examples/media/` and VPW-075 evidence screenshots instead of a live Workbench session.
3. Use the already generated build artifacts from the locked demo path and rerun only `report verify-evidence-bundle` against the ZIP if Docker is not available.
4. If a live provider is unavailable or rate-limited, keep using `data/demo_provider_snapshot.json` with locked provider data.
5. If a release gate fails for environmental reasons, record the failing command, environment detail, and retry decision in the issue/PR closeout instead of hiding the failure.

## Non-Goals And Known Limitations

- The Workbench is local-first and is not a hardened public internet deployment.
- Evidence bundles provide integrity checks, not encryption or detached signatures.
- Imported files may contain sensitive hostnames, package paths, image names, services, owners, and environment labels.
- ATT&CK context is source-backed defensive context only. Unmapped CVEs remain unmapped.
- The project does not scan infrastructure, run exploits, generate proof-of-concept steps, or use AI/fuzzy CVE-to-ATT&CK mapping.

## Closeout

VPW-076 is verified by this PR when:

- this evidence file is committed and linked from MkDocs,
- `archive/vpw-evidence/vpw-076-demo-evidence-bundle-verification.json`
  preserves the verification output in the archive,
- `CHANGELOG.md` records the added release-story evidence,
- `docs/releases/workbench-v1.0.0.md` explicitly lists Features, Non-Goals, and Known Limitations,
- `docs/workbench-v1-release-checklist.md` links the VPW-076 closeout evidence,
- historical `make demo-evidence-bundle-check` passed with `summary.ok=true`,
- `make docs-check` passes.
