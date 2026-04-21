# Current State Audit

Audit date: `2026-04-20`
Repository path: `<local private workspace clone>`

## Baseline State Before V0.3 Work

- current implementation branch: `<feature branch used for the local ATT&CK implementation>`
- baseline source commit: `4bf63ba`
- latest reachable tag before the V0.3 changes: `v0.2.2`
- baseline package version before edits: `0.2.2`
- important environment note: the local shell has `python3`, not `python`

## Commands Executed

```bash
pwd
git status --short
git branch --show-current
git tag --sort=creatordate | tail -n 5
python3 -m pytest -q
python3 -m vuln_prioritizer.cli --help
python3 -m vuln_prioritizer.cli analyze --help
python3 -m vuln_prioritizer.cli attack --help
```

## Observed Baseline Results

- `python3 -m pytest -q` passed with `49 passed` before the V0.3 code changes.
- The CLI baseline exposed only three top-level workflows: `analyze`, `compare`, and `explain`.
- The ATT&CK path at baseline was optional and CSV-only.
- `compare` was already present as a `CVSS-only vs enriched` view.
- The repository already had local quality gates and release-oriented `Makefile` targets.

## CLI Surface Found

Top-level help at baseline:

- `analyze`
- `compare`
- `explain`

Post-V0.3 implementation target:

- `analyze`
- `compare`
- `explain`
- `attack validate`
- `attack coverage`
- `attack navigator-layer`

## Known Gaps Before V0.3

- ATT&CK data came only from a local CSV file.
- No CTID Mappings Explorer JSON import existed.
- No ATT&CK technique metadata layer existed.
- `analyze` and `compare` did not surface ATT&CK context in a strong way.
- Reports lacked a dedicated ATT&CK summary section and mapped/unmapped counts.
- There was no ATT&CK-specific utility command.
- Demo evidence for ATT&CK was concentrated in `example_explain.json`; the main report and compare artifacts did not demonstrate the ATT&CK differentiator.

## Why V0.3 Was Needed

The project already worked as a CVSS/EPSS/KEV prioritizer. The V0.3 gap was not “missing polish”; it was the absence of the intended differentiator:

- a defensible CTID-based ATT&CK context layer
- visible mapped versus unmapped reporting
- stronger management-facing threat context
