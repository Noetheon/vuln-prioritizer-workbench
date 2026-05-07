# VPW-AUD-303 Security Path Redaction Evidence

Issue: VPW-AUD-303 / #414
Category: Security/Deployment
Date: 2026-05-07
Disposition: gap

## Scope

This evidence covers hardening of the shared redaction utility used by API error
projection, reports, manifests, and evidence bundle verification. The change is
limited to local filesystem path redaction for container, POSIX, and Windows
absolute path samples, including quoted paths and paths with spaces.

Out of scope: authentication, authorization, project membership, RCAB/RBAC, and
any deployment model change.

## Behavior Verified

- Shared text redaction now recognizes container paths rooted below `/app`.
- Shared text and value redaction continue to cover POSIX workspace, service,
  opt, state-directory, and Windows absolute path samples, including quoted paths
  and paths with spaces.
- API-safe request value redaction uses the shared value redaction path and
  removes embedded local path values.
- Workbench API-relative URLs remain visible in free text so user-facing finding
  links are not destroyed by the broader path redaction.
- Safe environment variable names such as `NVD_API_KEY` remain visible while
  path values are replaced with redaction placeholders.
- Evidence bundle verification redacts copied artifact text and warnings that
  contain synthetic container path samples before writing bundle artifacts.

## Validation Commands

```text
python3 -m pytest -q backend/tests/test_security_redaction.py backend/tests/test_evidence_bundle_verification.py::test_evidence_bundle_redacts_secret_like_text_in_copied_artifacts --no-cov
```

Result: `3 passed in 0.05s`

```text
python3 -m pytest -q backend/tests/api/test_template_github_issue_export.py::test_template_github_issue_preview_selected_findings_markdown_redacts_secrets --no-cov
```

Result: `1 passed in 0.17s`

```text
python3 -m pytest -q backend/tests/test_evidence_bundle_verification.py backend/tests/test_provider_snapshot_contract.py backend/tests/test_report_artifacts.py backend/tests/api/test_template_reports_api.py --no-cov
```

Result: `49 passed in 3.35s`

```text
make demo-evidence-bundle-check
```

Result: demo analysis, demo evidence bundle, and demo evidence bundle
verification completed successfully. Generated verification artifacts stayed
under the local build directory.

```text
make check
```

Result: Ruff format/check clean, mypy clean for 215 source files, and backend
tests passed with `962 passed, 4 skipped in 45.64s`. Coverage remained above the
required 90% threshold at `90.94%`.

```text
python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
```

Result: `5 passed in 0.20s`

```text
git diff --check
```

Result: no whitespace errors.

## Evidence Hygiene

The evidence above contains no secrets, tokens, cookies, customer data, or real
private filesystem paths. Path samples used by tests are synthetic and are only
used to verify redaction behavior.

## Residual Risk

None for the covered API/report/evidence redaction path. Redaction remains a
defense-in-depth layer and does not replace rooted artifact storage checks. The
issue requested `docs/evidence/security-path-redaction.md`; active repository
hygiene intentionally limits `docs/evidence` to canonical contract artifacts, so
this audit evidence is retained under the archived VPW evidence tree instead.

## Scorecard Impact

Before: Security/Deployment retained an audit gap where container-style runtime
paths and embedded absolute POSIX path values could be missed by shared
redaction.

After: Shared API/report/evidence redaction covers the audited path forms and is
backed by targeted tests plus the broader backend and evidence bundle gates.
