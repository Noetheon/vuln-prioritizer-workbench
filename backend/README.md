# Vuln Prioritizer Workbench

Vuln Prioritizer Workbench is a local-first workbench for explainable CVE
prioritization. It imports vulnerability evidence you already have, then ranks
findings with CVSS, EPSS, CISA KEV, asset context, VEX, waivers, and reviewed
defensive ATT&CK context. Every ranking is explained.

- **Inputs:** CVE lists, Trivy, Grype, CycloneDX, SPDX, Dependency-Check,
  GitHub alerts, Nessus, OpenVAS, VEX, and asset context.
- **Outputs:** Markdown, HTML, JSON, CSV, SARIF, ATT&CK Navigator, and Evidence
  ZIP reports.
- **Boundary:** It does not scan networks, run exploits, or patch anything.

## Install And Run

```bash
pipx install vuln-prioritizer-workbench
vpw serve
```

`vpw serve` opens the browser at `http://127.0.0.1:8765`. One process runs the
API, the browser app, database migrations, and the background worker, with
SQLite data in a private per-user directory. No Node.js, PostgreSQL, or Docker
is needed.

Other commands:

- `vpw import`: upload scanner or SBOM files from CI.
- `vpw backup` and `vpw restore`: create and restore verified backups.
- `vpw serve --help`: list runtime options.

A container image is published as
`ghcr.io/noetheon/vuln-prioritizer-workbench`. Small teams can share one
instance behind their own login proxy in team mode.

## Documentation

- [README and product tour](https://github.com/Noetheon/vuln-prioritizer-workbench#readme)
- [Installation](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/INSTALL.md)
- [Team mode](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/docs/team-mode.md)
- [Changelog](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/CHANGELOG.md)

## Package Layout

This distribution ships the `app` package only: the FastAPI Workbench API,
database migrations, packaged browser assets and resources, the supervised
worker, and the internal `app.domain.engine` modules. Repository-level docs,
fixtures, and maintainer tooling stay in the source repository.
