# VPW-AUD-301 API Token Inactive User Evidence

Issue: VPW-AUD-301 / #412
Category: Security/Deployment
Date: 2026-05-07
Disposition: gap

## Scope

This evidence covers service-token authentication when the configured API-token
principal has been deactivated. The change is limited to fail-closed handling for
inactive principals on existing project-scoped and admin service-token paths.

Out of scope: any work outside inactive-principal service-token handling.

## Behavior Verified

- Service tokens for `read`, `write`, `import`, `report`, and `admin` scopes are
  denied with HTTP 403 when the configured principal is inactive.
- Denied API-token attempts return `Inactive user` without echoing the raw token.
- Denied API-token attempts do not update `last_used_at`.
- Each denied token attempt records an `api_token.auth.failure` audit event with
  `status=failure`, `reason=inactive_user`, and the token record id as the
  resource id.
- Audit event details include scopes and the failure reason, but not raw token
  values.

## Validation Commands

```text
python3 -m pytest -q backend/tests/api/test_template_api_tokens.py::test_template_service_tokens_fail_closed_for_inactive_configured_user --no-cov
```

Result: `1 passed in 0.46s`

```text
python3 -m pytest -q backend/tests/api/test_template_api_tokens.py backend/tests/api/test_template_auth_smoke.py --no-cov
```

Result: `22 passed in 4.64s`

```text
make check
```

Result: Ruff format/check clean, mypy clean for 211 source files, and backend
tests passed with `937 passed, 4 skipped in 46.28s`. Coverage remained above the
required 90% threshold at `90.84%`.

```text
make docs-check
```

Result: release evidence hygiene passed and MkDocs built successfully. MkDocs
builds the public documentation tree while this audit evidence remains archived
outside `docs/evidence`.

## Evidence Hygiene

The evidence above contains no secrets, service-token values, cookies, customer
data, or private filesystem paths.

## Residual Risk

None for inactive-principal API-token handling.

## Scorecard Impact

Before: Security/Deployment retained a P0 fail-open service-token gap for
inactive principals.

After: The inactive-principal service-token path fails closed, preserves token
usage metadata, and leaves an audit trail for denied attempts.

Decision: This issue is ready for PR review after the evidence file, code, tests,
and GitHub Project #9 fields are linked.
