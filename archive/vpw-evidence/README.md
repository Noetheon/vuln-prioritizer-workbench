# VPW Evidence Archive

This directory preserves historical Vuln Prioritizer Workbench evidence files
that previously lived under `docs/evidence/`.

The files are intentionally outside the MkDocs `docs/` tree so the public
documentation stays focused on current user, maintainer, architecture, release,
and contract material. Use this archive only when reconstructing old VPW issue
evidence, screenshots, demo flows, or release closeout notes.

## Contents

- VPW issue evidence markdown from `vpw-029` through `vpw-085`.
- Historical screenshot sets for Workbench pages, final demo flows, and design
  system foundation work.
- Machine-readable evidence JSON, CSV, SARIF validation, and evidence-bundle
  verification artifacts.
- Presentation-pack and final-demo-flow indexes that point to the archived
  proof set.

## Update Policy

Do not write new screenshots here by default. Browser tests write to
`frontend/test-results/evidence/` unless `VPW_UPDATE_DOCS_EVIDENCE=1` is set.
Use that opt-in only for an intentional evidence refresh.
