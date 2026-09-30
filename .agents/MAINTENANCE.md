# Maintaining VPW agent guidance

The repository maintainer owns this guidance; authors of changes to an affected
boundary update its instructions in the same change. Code and current product
contracts determine facts. User-authorized changes can revise those contracts.

Canonical skills live in [skills](skills/). Codex discovers them here.
[AGENTS.md](../AGENTS.md) carries only shared project context.
[CLAUDE.md](../CLAUDE.md) imports it; generated Claude skill loaders point to the
same guides. Edit canonical files, then run
`python3 scripts/check_agent_skills.py --sync-claude` from the repository root
when discovery metadata changes or a skill is added.

Run `make agent-skills-check` after guidance changes. The lightweight CI job
[agent-guidance](../.github/workflows/agent-guidance.yml) runs the same check.
It catches broken local links, stale Make targets, changed frontend test runners,
invalid discovery fields, and divergent Claude loaders. It does not prove that
an instruction is useful or still matches product intent.

Keep product facts linked to maintained repository sources. Check instructions
when changing architecture, persistence, test runners, release processes, or
supported inputs. Model upgrades and repeated agent mistakes are reasons to
revisit affected guidance, not to append another universal rule. Prefer removing
obsolete advice or adding one observed pitfall with its reason.

The six old personal `vuln-prioritizer-*` skills are superseded: the maintainer
compass is now AGENTS.md; test-hardening and contract-harness are combined in
vpw-testing; review, security, and roadmap remain separate. Remove old personal
copies from discovery after backing them up. Do not install additional global
copies of these project skills: they would outlive their branch and duplicate
the repository's instructions. Other worktrees acquire this version through
normal Git integration. An already-running chat may still retain older text.

For a substantial instruction or model change, compare realistic tasks using the
same model/settings in independent sessions with and without the affected skill.
Use scratch checkouts and exclude external writes unless part of the evaluation.
Check outcome, unnecessary questions, check selection, time, and token use.
Repeat enough to distinguish a consistent result from a single lucky run.

| Evaluation request | Expected behavior |
| --- | --- |
| Change a label in the VPW UI | Small edit and relevant verification; no release/security program |
| Audit whether decision storage should be redesigned | Evaluate alternatives; no obligation to preserve named tables or modules |
| Fix local Grype matching of an uploaded SBOM | Recognize supported inventory matching; do not reject it as host probing |
| Improve one import-to-report regression test | Exercise the owning API/worker path with controlled inputs |
| Run one frontend unit test | Use the unit runner and verify collection, not a Playwright success claim |
| Remove a hygiene assertion for a retired requirement | Remove it with the requirement; no meaningless replacement assertion |
| Review a migration of existing local project data | Check migration/recovery behavior; no assumption that beta data is disposable |
| Close a GitHub issue after a specifically authorized merge | Verify the exact merge and acceptance evidence; avoid a repeated permission loop |

These are evaluation cases and a rubric, not a claim that model comparisons
have been run. The CI check tests mechanical drift, not agent intelligence.

Design references, checked 2026-09-23:
[Anthropic: practical skill design](https://claude.com/blog/lessons-from-building-claude-code-how-we-use-skills),
[Anthropic: context engineering](https://claude.com/blog/the-new-rules-of-context-engineering-for-claude-5-generation-models),
[Anthropic: instruction anti-patterns](https://claude.com/blog/reducing-cost-and-improving-performance-with-claude-platform),
[OpenAI: revisiting skills](https://developers.openai.com/blog/rethinking-skills-and-prompts-for-gpt-6-astra).
