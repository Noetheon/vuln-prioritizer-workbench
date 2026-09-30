---
name: vpw-roadmap
description: Execute VPW GitHub issues or requested roadmap closeout.
---

Use when the task is explicitly organized around GitHub issues, milestones,
Project fields, or formal closeout. Ordinary local work does not need this process.

Read the referenced issue and acceptance criteria, then check the implementation
and current repository state. [Current product state](../../../docs/current-product-state.md)
separates active behavior from historical plans; an old completion note is not
proof for a new candidate. The user may explicitly change the product direction.

Use [the repository PR template](../../../.github/pull_request_template.md) for a
requested GitHub handoff. Describe the delivered behavior, affected surfaces,
validation, and remaining work. Group related issues when that matches the task;
do not impose a fixed branch or PR count.

Keep implementation, checks, merge status, issue closure, and publication distinct.
Verify the exact PR/commit before reporting completion. An existing authorization
to finish the work should not produce a second permission loop. Posting comments,
changing Project fields, or closing issues must be part of the requested scope.
