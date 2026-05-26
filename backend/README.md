# Vuln Prioritizer Backend

This backend workspace packages the active FastAPI Workbench API, database
migrations, supporting services, and the shared `vuln_prioritizer` domain
library used by the Workbench runtime.

The published backend distribution intentionally includes both
`src/vuln_prioritizer/**` and `app/**`. The old CLI entrypoint is not an active
package surface; package checks validate that the wheel and sdist match this
Workbench-plus-domain-library boundary.

Repository-level docs, fixtures, demo artifacts, and maintainer commands remain
at the repository root.

When backend behavior is referenced from documentation, verify the claim through
the repository-level
[`docs/documentation-evidence-matrix.md`](../docs/documentation-evidence-matrix.md)
before treating historical CLI, template, or archive material as current
Workbench evidence.
