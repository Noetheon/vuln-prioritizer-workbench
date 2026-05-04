# VPW-052 Evidence Bundle Verification

VPW-052 documents the integrity verification surface for evidence bundles. It
adds the template-stack report verification API for VPW-051 ZIP reports and
records how operators verify a generated ZIP, how tampering is reported, and
which evidence paths should be archived with release or review records.

## Verify Command Scope

The CLI verification contract is:

```bash
vuln-prioritizer report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

Equivalent module execution is supported:

```bash
python3 -m vuln_prioritizer.cli report verify-evidence-bundle \
  --input evidence.zip \
  --format json \
  --output evidence-verification.json
```

The command reads the embedded `manifest.json`, validates the manifest shape,
recomputes SHA-256 and byte size for each declared ZIP member, and reports:

- `ok` for members matching the manifest.
- `missing` for declared members absent from the ZIP.
- `modified` for declared members with byte-size or SHA-256 drift.
- `unexpected` for extra members not declared in the manifest.
- `error` for malformed or invalid manifests.

JSON output follows
`docs/schemas/evidence-bundle-verification-report.schema.json` with
`metadata`, `summary`, and `items`. The command exits with `0` when
`summary.ok=true` and exits with `1` when integrity problems are detected.

## API and Workbench Scope

The template Workbench API exposes verification for stored evidence bundle
reports through the authenticated report surface:

- `POST /api/v1/runs/{run_id}/reports` creates report artifacts, including an
  evidence ZIP when the requested format is `zip`.
- `GET /api/v1/reports/{report_id}/download` downloads the managed bundle.
- `POST /api/v1/reports/{report_id}/verify` verifies the stored bundle and
  returns the same JSON-ready `metadata`, `summary`, and `items` shape as the
  CLI verification report.

Workbench verification is scoped to server-owned evidence bundle records. Before
member-level verification runs, the stored artifact path is resolved under the
configured report directory and checked against the database SHA-256. VPW-052
does not add an arbitrary upload or remote URL verification endpoint.

The legacy local-first Workbench artifact API still exposes
`GET /api/evidence-bundles/{bundle_id}/verify` for its own `EvidenceBundle`
records. The duplicate VPW-052 closure is based on the template-stack endpoint
above, not on that older surface alone.

The GitHub Action mirrors the local file contract with
`mode: verify-evidence-bundle`; it reads one ZIP from the CI workspace and
writes a JSON verification report.

## Positive Verification Evidence

The checked-in VPW-051 sample bundle verifies successfully:

```bash
python3 -m vuln_prioritizer.cli report verify-evidence-bundle \
  --input docs/evidence/vpw-051-evidence-bundle.zip \
  --format json \
  --output docs/evidence/vpw-052-positive-verification.json
```

Observed summary:

```json
{
  "expected_files": 4,
  "manifest_errors": 0,
  "missing_files": 0,
  "modified_files": 0,
  "ok": true,
  "total_members": 5,
  "unexpected_files": 0,
  "verified_files": 4
}
```

Verified members:

- `analysis.json`
- `technical.md`
- `executive.html`
- `provider-snapshot.json`

The fifth ZIP member is `manifest.json`, which is parsed as the integrity
source instead of being counted as a declared artifact file.

## Manipulated Bundle Evidence

A negative verification run was produced by copying the VPW-051 ZIP and changing
one byte sequence inside `analysis.json` while leaving `manifest.json` intact.
The verifier detected the modified member:

```bash
python3 -m vuln_prioritizer.cli report verify-evidence-bundle \
  --input build/vpw-052-evidence/tampered-evidence-bundle.zip \
  --format json \
  --output docs/evidence/vpw-052-tampered-verification.json
```

Observed summary:

```json
{
  "expected_files": 4,
  "manifest_errors": 0,
  "missing_files": 0,
  "modified_files": 1,
  "ok": false,
  "total_members": 5,
  "unexpected_files": 0,
  "verified_files": 3
}
```

The failing item was:

```json
{
  "path": "analysis.json",
  "status": "modified",
  "detail": "Archive member does not match the manifest: sha256 mismatch."
}
```

This demonstrates checksum-based tamper detection. It is not a signature,
timestamp authority, or external provenance attestation.

## Safe ZIP Verification Without Extraction

Verification is intentionally read-only against the ZIP archive:

- The verifier opens the ZIP and reads member bytes directly with the standard
  ZIP reader.
- It does not call filesystem extraction APIs and does not write ZIP members to
  disk.
- Expected paths come from the parsed manifest and are compared to ZIP member
  names.
- Unexpected members are reported instead of being materialized.
- Workbench API verification only targets managed artifacts after rooted path
  and stored SHA-256 validation.

This keeps verification suitable for local release evidence and CI workspaces:
operators can inspect integrity without expanding attacker-controlled filenames
into the filesystem.

## Relevant Evidence Paths

Checked-in source evidence:

```text
docs/evidence/vpw-051-evidence-bundle.zip
docs/evidence/vpw-051-manifest.json
docs/evidence/vpw-051-analysis.json
docs/evidence/vpw-051-evidence-bundle.md
docs/evidence/vpw-052-positive-verification.json
docs/evidence/vpw-052-tampered-verification.json
docs/schemas/evidence-bundle-manifest.schema.json
docs/schemas/evidence-bundle-verification-report.schema.json
```

Local VPW-052 manipulation artifact generated during this documentation pass:

```text
build/vpw-052-evidence/tampered-evidence-bundle.zip
```

Archive release evidence with repository-relative paths, the command output,
the verification JSON, and the SHA-256 of the verified ZIP. A passing bundle
must show `summary.ok=true` with zero missing, modified, unexpected, and
manifest-error counts.
