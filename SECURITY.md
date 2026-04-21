# Security Policy

## Supported Use

`vuln-prioritizer` is a defensive prioritization CLI for known CVEs. It is not a scanning engine, exploit framework, or asset discovery platform.

## Reporting a Security Issue

If you discover a security issue in this repository, do not open a public bug report first.

Preferred disclosure path:

1. Use GitHub private vulnerability reporting or a GitHub security advisory draft if that repository feature is enabled.
2. If private reporting is not available, contact the repository owner privately through the GitHub profile or repository security contact path before any public disclosure.

Avoid posting proof-of-concept exploit details, weaponized payloads, or sensitive reproduction steps in public issues.

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

## Maintainer Response Expectations

- Initial acknowledgement should happen as soon as practical.
- Public discussion should wait until impact and mitigation are understood.
- Fix publication should avoid revealing unnecessary exploit detail before users have a reasonable update path.

## Project-Specific Notes

- The tool consumes public vulnerability data from NVD, FIRST EPSS, and CISA KEV.
- Network integrations should remain limited to documented, official sources.
- Optional ATT&CK support must stay offline-mapping-based unless the project explicitly adopts a reviewed live approach.
