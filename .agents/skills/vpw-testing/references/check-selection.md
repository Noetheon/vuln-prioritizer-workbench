# Selecting VPW checks

Use the project's configured Python environment. Inspect [the Makefile](../../../../Makefile)
for current target definitions and [frontend scripts](../../../../frontend/package.json)
for current runners; do not copy a historical command when those definitions changed.

| Changed surface | Focused check | Broaden when relevant |
| --- | --- | --- |
| Backend behavior | Selected pytest files, using `--no-cov` for focused iteration | `make check` |
| Backend types | `make typecheck` | Backend gate if the change spans behavior |
| Frontend logic | Node unit tests; `make frontend-test-unit` runs the unit suite | `make frontend-check` |
| Browser behavior | A matching Playwright spec through the frontend npm wrapper | `make playwright-check` |
| OpenAPI/client | `make api-client-drift-check` | Regenerate and test the consuming API/UI change |
| Packaged frontend | `make runtime-assets-check` | Sync assets when the source UI changes |
| Documentation | A relevant docs test or `make docs-check` | A runtime check only when the claim depends on it |
| Decision rules and evidence quality | `make property-check`; affected `mutation-core-check` or `mutation-evidence-check` | `make mutation-check property-extended-check` |
| Retained history / persistence | `make recovery-check history-performance-check` | `make performance-smoke history-performance-extended-check` |
| Real local SBOM matching | `make grype-integration-check` (networked setup, isolated DB) | Inspect scanner/DB hashes and all three executed contracts |
| Agent guidance | `make agent-skills-check` | Behavioral comparison when instructions materially change |

The frontend's `test:unit` script uses Node's test runner for `.test.ts` files.
Its `test` script uses Playwright for `.spec.ts` files. Passing unit-test paths
to the browser runner can return zero tests. Confirm that a selected test was
actually collected; a process exit alone is insufficient evidence.
Use [the frontend npm wrapper](../../../../scripts/frontend-npm.sh) or Make
targets to select the project's toolchain rather than relying on system Node.

Select broader checks from changed behavior, risk, and the requested delivery.
Once relevant checks pass, repeat or expand them only for new changes, failures,
or unresolved concerns. Follow the applicable release/CI requirements when that
delivery is requested; a small local edit does not need a release rehearsal.

See the [testing strategy](../../../../docs/testing-strategy.md) for generated
profiles, resource ceilings and CI selection. Run history/performance separately
from mutation on the same machine. A mutation timeout or signal is a failed gate,
not a killed mutant; source-bound equivalent reviews are a separate result.
