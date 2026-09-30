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
