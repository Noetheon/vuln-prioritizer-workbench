# Reviewer Checklist

This checklist helps reviewers assess the final submission quickly and
reproducibly.

## Build, Tests, Docs

- [ ] Frontend build passes: `npm --prefix frontend --workspaces=false --engine-strict=true run build`
- [ ] Frontend lint passes: `npm --prefix frontend --workspaces=false --engine-strict=true run lint`
- [ ] Frontend unit tests pass: `npm --prefix frontend --workspaces=false --engine-strict=true run test:unit`
- [ ] UI smoke passes: `npm --prefix frontend --workspaces=false --engine-strict=true run test -- tests/ui-smoke.spec.ts`
- [ ] Backend report contracts pass:
      `python3 -m pytest -q backend/tests/api/report_contracts --no-cov`
- [ ] Backend smoke subset passes.
- [ ] Docs hygiene passes:
      `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov`
- [ ] MkDocs builds successfully: `python3 -m mkdocs build --clean`
- [ ] `make docs-check` passes.

## Scope And Integrity

- [ ] No manual edits in generated files under `frontend/src/client/**`.
- [ ] Any `frontend/src/api-client.ts` changes are reviewed as manual wrapper
      source, not generated-client drift.
- [ ] No unintended backend implementation changes.
- [ ] No changes to `data/attack/**`.
- [ ] No changes to contract artifacts under `docs/evidence/`.
- [ ] No screenshots or large artifacts in the submission PR.

## Product Claims

- [ ] VPW is described as prioritization for known CVEs, not as a scanner.
- [ ] Scoring is described as transparent and rule-based.
- [ ] No ML/AI black-box claims.
- [ ] CVSS, EPSS, KEV, asset context, provider freshness, VEX, and waivers are
      documented as visible signals.
- [ ] Evidence Center, reports, manifest, and checksums are documented.

## ATT&CK/TTP Safety

- [ ] Unmapped CVEs remain unmapped.
- [ ] No heuristic or LLM-based ATT&CK inference is claimed.
- [ ] Curated mapping is described as defensive context.
- [ ] No exploit, payload, PoC, or active probing material is included.
- [ ] Mapped TTP context is not interpreted as local exploitation.

## Evidence And Demo

- [ ] Final Demo Flow is linked.
- [ ] Presentation Pack is linked.
- [ ] Design-system evidence is linked.
- [ ] Contract artifacts under `docs/evidence/` are linked.
- [ ] Fallback demo without a live system is possible.

## Limitations

- [ ] Demo data is clearly marked as sample/evidence data.
- [ ] Public-production readiness is not claimed unless the current release or
      deployment candidate has fresh public evidence and residual-risk
      acceptance.
- [ ] Detection coverage is not overstated as proof of effectiveness.
- [ ] Waivers are described as governance context, not as risk deletion.

## Review Result

If all points are satisfied, the project can be assessed as
implementation-complete and submission-ready for the current phase. Additional
engineering refactors should be prioritized after the submission.
