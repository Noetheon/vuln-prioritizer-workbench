# Support

Use the right channel so the repository stays readable and maintainable.

## Usage Questions

Use GitHub Discussions for:

- installation questions
- workflow guidance
- CI integration questions
- help choosing commands or output formats

Start with the repo docs first:

- [README.md](README.md)
- [docs/index.md](docs/index.md)
- [docs/playbooks.md](docs/playbooks.md)

## Bugs And Feature Requests

Use GitHub Issues for:

- reproducible bugs
- behavioral regressions
- scoped feature requests
- documentation fixes

Before opening an issue, include the exact command, input format, observed output, expected output, Python version, and OS when relevant.

## Security Reports

Do not open public issues for security vulnerabilities in the CLI, release workflow, or repository configuration.

Use GitHub private vulnerability reporting for this public repository. If that flow is temporarily unavailable, follow [SECURITY.md](SECURITY.md).

## Scope Reminder

`vuln-prioritizer` is a local-first CLI for prioritizing known CVEs and existing findings. It is not a scanner, SaaS platform, or heuristic CVE-to-ATT&CK mapper.
