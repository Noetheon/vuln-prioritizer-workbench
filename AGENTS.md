# Working on VPW

VPW is a local-first vulnerability-prioritization Workbench. For product scope
and architecture questions, start with [current product state](docs/current-product-state.md)
and verify the affected behavior in this checkout. Current implementation and
historical plans are evidence, not restrictions on an authorized redesign.

Project-specific pitfalls:

- Local Grype matching of uploaded SBOMs is supported; distinguish it from
  scanning hosts or networks. Provider refresh, decision reevaluation, and SBOM
  reassessment are different operations.
- Preserve the distinction between current decisions and what an earlier run
  recorded. A storage redesign must account for affected history and reports;
  it need not retain particular modules, tables, or JSON layouts.
- A beta label does not make local databases disposable. Check migration and
  recovery implications when changing persisted data.
- ATT&CK mappings need explicit reviewed provenance; do not infer them with an LLM.
- [The API client](frontend/src/client/) is generated. Use
  [the wrapper](frontend/src/api-client.ts) for handwritten integration changes.

Use the configured project Python environment and the toolchain selected by
[the Makefile](Makefile) / [frontend npm wrapper](scripts/frontend-npm.sh).
Check only the surfaces relevant to the task and any required delivery gates.
Frontend unit and browser tests use different runners; see the verification guide
when selecting checks.

Load these guides only for the matching task:

- [Review and readiness](.agents/skills/vpw-review/SKILL.md)
- [Test improvement and contract coverage](.agents/skills/vpw-testing/SKILL.md);
  [check selection](.agents/skills/vpw-testing/references/check-selection.md) for verification commands
- [Security boundary review](.agents/skills/vpw-security-review/SKILL.md)
- [GitHub issue and roadmap execution](.agents/skills/vpw-roadmap/SKILL.md)

Guidance ownership, drift checks, and evaluation cases:
[maintaining these instructions](.agents/MAINTENANCE.md).

## Public publication privacy

- Use a pseudonymous Git author and a GitHub `users.noreply.github.com` address for new commits.
- Use synthetic people, affiliations and paths in examples and tests (for example `/Users/example/`).
- Before publishing, inspect source files, PDFs and their metadata, images, archives, commit/tag metadata, issue/PR text, and release/CI outputs for personal information.
- Keep personal detection patterns outside Git. Do not commit a blacklist containing the private names or addresses it is intended to protect.
- Never paste raw terminal logs with personal directory names into issues or pull requests. Replace those paths before publication.
- Run the local privacy guard before commit/push and before uploading documents or release files. The generic CI check complements this; it does not replace personal-pattern checks or image/PDF review.
- History rewrites require a verified backup and checking server-held PR references and cached commits before making a repository public again.
