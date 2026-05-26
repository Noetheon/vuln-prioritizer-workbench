# VPW Evidence Archive

This directory preserves selected historical Vuln Prioritizer Workbench evidence
files that previously lived under `docs/evidence/`.

The files are intentionally outside the MkDocs `docs/` tree so the public
documentation stays focused on current user, maintainer, architecture, release,
and contract material. Use this archive only when reconstructing old VPW issue
evidence, screenshots, demo flows, or release closeout notes.

Archived evidence is not current release certification by itself. Verify current
claims through `docs/documentation-evidence-matrix.md`, current tests, and exact
command output before copying archived language into active docs.

## Contents

This archive has been intentionally reduced to the smallest set still useful for
current documentation hygiene:

- Archive entrypoints: this README, `MANIFEST.md`, and
  `BINARY-MANIFEST.json`.
- Small historical demo/presentation summaries under `final-demo-flow/` and
  `presentation-pack/`.
- Selected issue-level Markdown evidence still referenced by current docs.
- `vpw-051-evidence-bundle.zip`, the tiny historical bundle still referenced by
  `docs/evidence/vpw-052-positive-verification.json`.

Large screenshot sets, design-system proof images, duplicate JSON/CSV exports,
and broad visual presentation assets were pruned from `main`. They were useful
for the original submission story, but they are not required to prove current
Workbench behavior.

## Update Policy

Do not write new screenshots here by default. Browser tests write to
`frontend/test-results/evidence/` unless `VPW_UPDATE_DOCS_EVIDENCE=1` is set.
Use that opt-in only for an intentional evidence refresh. Do not add audit
scorecards, intermediate handoff notes, or one-off validation summaries here by
default; use PR/issue comments or CI artifacts unless a durable repository
artifact is explicitly needed.

Run `python3 scripts/check_archive_evidence_manifest.py` after changing tracked
binary evidence. The manifest check verifies tracked binary hashes, ZIP member
safety, and purpose labels; it does not validate that a screenshot still matches
the current Workbench UI.
