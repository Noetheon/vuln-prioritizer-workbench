# Security Policy

## Supported Use

`vuln-prioritizer` is a defensive prioritization CLI and local self-hosted
Workbench for known CVEs and imported findings. It is not a scanning engine,
exploit framework, or asset discovery platform.

The Workbench is local-first and self-hosted by default. Treat it as a trusted
single-workspace operator tool unless a specific deployment hardening review has
covered TLS/proxy configuration, backup and restore, audit retention, token
handling, role boundaries, upload/download storage, and the published threat
model.

The project does not accept changes that turn the tool into an exploit runner,
PoC generator, credential tester, active network probe, attack simulator,
autopatcher, or heuristic/AI CVE-to-ATT&CK mapper.

## Reporting a Security Issue

If you discover a security issue in this repository, do not open a public bug report first.

Preferred disclosure path:

1. Use GitHub private vulnerability reporting for this public repository.
2. If that GitHub flow is temporarily unavailable, contact the repository owner privately through the GitHub profile or repository security contact path before any public disclosure.

Avoid posting proof-of-concept exploit details, weaponized payloads, or sensitive reproduction steps in public issues.

Safe disclosure guidance:

- Report the minimum reproduction detail needed to confirm impact.
- Redact tokens, cookies, API keys, private scan exports, customer names,
  internal hostnames, and absolute local paths.
- Prefer synthetic files or sanitized exports when a parser/import issue is
  involved.
- Do not attach exploit payloads, live target details, public proof-of-concept
  links, or instructions for active exploitation to public tickets.

## Supported Versions

| Version line | Status |
| --- | --- |
| `1.x` | supported |
| `< 1.0.0` | best effort only |

## Expected Reporter Content

Include, when possible:

- affected version or commit
- clear impact summary
- exact reproduction prerequisites
- whether the issue affects the CLI itself, packaging, release workflow, or repository configuration
- whether the issue requires local Workbench access, API-token access, a crafted
  input file, or a specific deployment configuration
- whether the issue touches Workbench API/auth behavior, uploads, report
  downloads, evidence bundles, provider snapshots, or generated artifacts

## Maintainer Response Expectations

- Initial acknowledgement should happen as soon as practical.
- Public discussion should wait until impact and mitigation are understood.
- Fix publication should avoid revealing unnecessary exploit detail before users have a reasonable update path.

## Project-Specific Notes

- The tool consumes public vulnerability data from NVD, FIRST EPSS, and CISA KEV.
- Network integrations should remain limited to documented, official sources.
- Optional ATT&CK support must stay offline-mapping-based unless the project explicitly adopts a reviewed live approach.
- XML, SBOM, scanner, and advisory inputs are treated as local exported evidence
  files. The tool must not scan remote systems to create those files.
- Public internet deployment is out of scope until the threat model and
  operational hardening documents explicitly say otherwise.
