---
name: vpw-review
description: Review VPW code or assess PR/release readiness.
---

Review the requested change or architecture question against the user's intended
behavior. An open architecture audit should challenge the existing design.
Ordinary implementation does not need a separate readiness review by default.

For disputed product scope, use [current product state](../../../docs/current-product-state.md)
and the affected code. For published behavior, use [contracts](../../../docs/contracts.md).
Read only the sources needed for the change.

High-value review boundaries in this project:

- Does a change keep finding identity, current state, historical reports, and
  explicit user overrides coherent across the affected surfaces?
- Could import, waiver, asset, or provider changes amplify work or storage as
  project size and history grow? Measure before prescribing a performance limit.
- Do API changes reach the generated client and handwritten wrapper? Does a
  packaged UI change include the required runtime assets?
- Does a schema change preserve or explicitly migrate existing project data?

When running checks, use [check selection](../vpw-testing/references/check-selection.md).
Expand validation for changed surfaces, failed checks, or a requested release;
a routine handoff alone does not require every gate.

Report actionable findings with a location, trigger, and consequence. Separate
observed defects, design tradeoffs, and untested assumptions. A passing local
check does not establish hosted CI status, release publication, or deployment safety.
