# VPW-072 Performance Smoke Evidence

Issue: VPW-072 / #178

Date: 2026-04-30

Branch: `codex/vpw-072-performance-smoke`

## Scope

VPW-072 adds an explicit optional performance smoke for the template Workbench API:

- synthetic 10k `generic-occurrence-csv` fixture generation
- locked-provider import through `/api/v1/projects/{project_id}/imports`
- dedupe-key creation and score/explain persistence for 10,000 findings
- stable high-offset findings pagination through `/api/v1/projects/{project_id}/findings/`
- documented MVP thresholds and machine-readable output

The smoke is opt-in and is not part of default `make check`.

## Command

```bash
make performance-smoke
```

Output artifact:

- `build/vpw-072-performance-smoke.json`
- archived copy: `archive/vpw-evidence/vpw-072-performance-smoke.json`

## Result

The local VPW-072 run passed.

| Metric | Threshold | Measured |
| --- | ---: | ---: |
| Rows / findings | 10,000 | 10,000 |
| Import seconds | <= 60.0 | 1.1442 |
| Tail page seconds | <= 1.0 | 0.2420 |
| Repeat tail page seconds | <= 1.0 | 0.2518 |
| Peak RSS delta | <= 512 MiB | 208.594 MiB |

The tail page at offset `9900` returned 100 items and repeated with the same finding IDs.

## Implementation Notes

Large all-new occurrence imports now use a bulk persistence path when the import has at least 1,000 rows, no component rows, no existing dedup-key matches, and no ATT&CK context persistence. The path:

- preloads existing dedup keys, assets, and vulnerabilities in chunks
- inserts assets, findings, and occurrences in bounded batches
- samples dedup decisions in the run summary while preserving full `decision_count`
- stores compact per-finding score/explain JSON for the bulk path and keeps provider details normalized on vulnerability records

Small imports and imports requiring component, existing-finding update, or ATT&CK context behavior continue through the standard ORM path.

## Residual Risk

This is an MVP smoke, not a full load benchmark. It covers deterministic local SQLite/TestClient behavior with locked provider data. Follow-up scale work should measure Postgres, mixed create/update imports, component-heavy scanner data, and concurrent users.
