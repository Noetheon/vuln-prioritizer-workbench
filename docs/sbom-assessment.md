# Local SBOM assessment

Upload a CycloneDX JSON or SPDX 2.x JSON inventory and select the optional
Grype assessment. The Workbench runs your configured local Grype executable,
then prioritizes its CVE matches through the existing provider, context, VEX
and Decision Ledger pipeline. It does not inspect a host or container, infer
runtime reachability, or guarantee that the inventory is complete.

## Setup and operation

Install a trusted Grype release for your platform using the
[official installation guidance](https://oss.anchore.com/docs/installation/).
Verify release checksums. The Workbench does not install or silently update
scanner executables. The integration is verified with Grype 0.110.0; other
versions need the same JSON/configuration contracts and should be validated
before use.

Configure the environment before starting `vpw serve`:

```sh
export SBOM_GRYPE_EXECUTABLE=/absolute/path/to/grype
export SBOM_SCAN_TIMEOUT_SECONDS=300
export SBOM_SCAN_MAX_OUTPUT_MB=64
vpw serve
```

The default executable is `grype` on `PATH`. The managed scanner database is
stored in the `grype` subdirectory of the Workbench provider cache directory.
It is separate from NVD/EPSS/KEV provider snapshots. The upload option to update
the scanner database permits database downloads; it does not upload the SBOM.
With that option disabled, a valid local database is required. An absent or
stale database fails the assessment rather than producing a clean result.
Normal CVE enrichment still follows the selected Workbench provider mode.
Locked provider snapshots must cover the newly discovered CVEs; incomplete
locked snapshots fail explicitly. Unlocked operation may use provider network
fallbacks, and missing provider data remains visible in the decision evidence.

Only named, nonempty component/package inventories are accepted. PURLs,
versions and distribution metadata materially affect matching. Missing
identifiers or version information produces an explicit partial assessment.
The identification counter is a metadata-quality measure, not proof that a
scanner supports or fully checked every package.

## Upload and results

Select `cyclonedx-json` or `spdx-json`, enable Grype, and enter a stable subject
such as `orders-service@2026.09`. Use the same subject for the same software
release. Upload filenames and temporary scanner paths are not finding scope.
An API caller may omit the subject: metadata identity or the original SBOM
content hash supplies a stable fallback.

The multipart import endpoint accepts these additive fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `sbom_scanner` | `none` | `grype` enables local inventory matching. |
| `sbom_target_ref` | metadata/hash | Stable software subject; required by the UI. |
| `sbom_db_update` | `true` | Permit Grype database downloads before matching. |

Without the scanner option, the existing SBOM import path still requires
embedded CVE vulnerability records. Enabling matching uses Grype's report as
the finding source; it does not silently merge embedded vulnerability records
or embedded VEX with the scanner results. Use the explicit VEX sidecar for
Workbench VEX decisions.

The run displays scanner matches, matches with CVE mappings and matches without
CVE mappings separately. One match may yield several CVE findings, and several
matches may converge on one finding scope. A successful zero-match assessment
is distinct from a failed scan. Unassigned advisories remain in the original
report and make the assessment partial; they are not prioritized as CVEs.

`AnalysisEvidenceV2.sbom_assessment` stores the versioned `sbom-assessment.v1`
manifest, with scanner/database provenance, hashes, counts, limitations and
timestamps. The regular analysis JSON includes it in the run summary.
`GET /api/v1/runs/{run_id}/sbom-evidence` downloads the original inventory,
scanner report, assessment and integrity manifest. This download includes raw
package metadata; review it before sharing. Ordinary report bundles retain
their existing source-file redaction policy.

## Rescans and failure recovery

`POST /api/v1/runs/{run_id}/sbom-rescans` accepts
`{"sbom_db_update": true}` and queues a new run from the hash-verified retained
inventory. It preserves the subject and original observation time, records
new scan/evaluation times and links to its source run. It can discover newly
known vulnerabilities. Reevaluation of existing findings is a separate action.
Rescans do not establish that old software was freshly observed in production;
missing matches do not automatically close old findings as fixed.

Scanner processes have bounded output and runtime. Cancellation, shutdown and
lost worker ownership stop the process; a worker shutdown requeues unfinished
work. Explicit failures remain visible and can be retried after correcting the
binary, database or input. Each completed attempt retains separate scanner
artifacts. Back up the database and managed uploads together to preserve the
decision history and its original evidence.

See the [implementation and validation record](architecture/sbom-assessment-plan.md).

## Reproducible examples

The repository includes deliberately vulnerable
[CycloneDX](examples/sbom-vulnerable.cdx.json) and
[SPDX](examples/sbom-vulnerable.spdx.json) inventories for lodash 4.17.20 and
log4j-core 2.14.1, plus a [small inventory](examples/sbom-zero.cdx.json) that
produced no matches in the recorded validation. Results may change with the DB.

To exercise the real HTTP upload, worker and ZIP path in an isolated test
database, provide an installed binary and an already populated Grype DB cache:

```sh
VPW_TEST_GRYPE_BINARY=/absolute/path/to/grype \
VPW_TEST_GRYPE_DB=/absolute/path/to/grype-cache \
VPW_SBOM_VALIDATION_OUTPUT=build/sbom-validation \
.venv/bin/python -m pytest backend/tests/live/test_sbom_live_contract.py --no-cov -q
```

This opt-in gate disables scanner DB downloads and uses the deterministic demo
snapshot for downstream providers. It verifies real scanner integration, not
live NVD/EPSS/KEV availability or complete provider coverage.
