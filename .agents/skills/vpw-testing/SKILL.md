---
name: vpw-testing
description: Improve VPW tests, fixtures, or contract coverage.
---

Use for a testing task: regression protection, flaky tests, coverage gaps, or
import/report/workflow contract work. A small implementation can use its existing
targeted tests without loading this whole workflow.

Reuse [backend helpers](../../../backend/tests/utils/) and the owning suites:
[imports](../../../backend/tests/api/import_contracts/),
[reports](../../../backend/tests/api/report_contracts/), and
[workflows](../../../backend/tests/api/workflow_contracts/).
Choose the smallest slice that demonstrates the behavior at issue.

Known pitfalls:

- For an Import -> Findings -> Report contract, drive the real API and worker
  path. Seeding final database rows can bypass the behavior the test claims to verify.
- An accepted queued request is not a completed workflow or a produced artifact.
  Assert the relevant terminal outcome using existing workflow helpers.
- Test current reads and historical run reads according to their separate
  contracts. Do not freeze today's storage layout as the required architecture.
- Provider/network responses and time-dependent inputs need controlled fixtures
  for repeatable tests; live-provider checks are a separate requested exercise.
- Remove obsolete assertions when their requirement is retired. Preserve coverage
  of behavior that is still required, rather than replacing every old assertion.
- Performance regressions need representative finding counts and accumulated
  history, not just a generous single-run timeout. Use the supported gzip export
  for large archive reports while retaining the plain-report size limit.
- Generated properties need independent positive/negative expectations. Add a
  minimized ordinary regression when a generated case exposes a real defect.
- For a reproducible defect, demonstrate the regression before and after the fix.
  Explain a manual-only exception with owner and follow-up. Quality-policy changes,
  removed tests and new critical entry points need the source-bound reasoning in
  [continuous quality assurance](../../../docs/quality-assurance.md).

Use [check selection](references/check-selection.md) for runners and broader gates.
Report which failure or missing behavior the changed test demonstrates, the
checks actually run, and any remaining uncertainty.
