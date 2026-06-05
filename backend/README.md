# Vuln Prioritizer Workbench Backend

This backend workspace packages the active FastAPI Workbench API, database
migrations, supporting services, and the internal `app.domain.engine` domain
modules used by the Workbench runtime.

The published backend distribution is `vuln-prioritizer-workbench` and ships the
`app/**` package only. Old CLI/package namespaces are not compatibility
surfaces; package checks validate that the wheel and sdist do not publish the
removed `vuln_prioritizer` tree.

Repository-level docs, fixtures, demo artifacts, and maintainer commands remain
at the repository root.

When backend behavior is referenced from documentation, verify the claim through
the repository-level
[`docs/documentation-evidence-matrix.md`](../docs/documentation-evidence-matrix.md)
before treating historical CLI, template, or archive material as current
Workbench evidence.
