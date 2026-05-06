# Vuln Prioritizer Backend

This backend workspace packages the `vuln_prioritizer` Python CLI, FastAPI
Workbench API, database migrations, and supporting services for the active
`backend/app` runtime.

The published backend distribution intentionally includes both
`src/vuln_prioritizer/**` and `app/**`. It is not a CLI-only package; package
checks validate that the wheel and sdist match this boundary.

Repository-level docs, fixtures, demo artifacts, and maintainer commands remain
at the repository root.
