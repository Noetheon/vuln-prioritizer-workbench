---
name: vpw-security-review
description: Review VPW security boundaries or deployment changes.
---

Use for an explicit security review or a change whose security boundary needs
assessment. Match the depth to the changed boundary; local feature work does not
implicitly require a public-deployment hardening program.

Use [the threat model](../../../docs/workbench-threat-model.md) for boundaries and
[deployment guidance](../../../docs/workbench-public-deployment.md) for exposure.
Resolve conflicts against the current code and the user's requested scope.

Project-specific checks, selected by the change:

- Imports and uploaded SBOMs are untrusted data. Check parsing bounds, archive
  handling, and the fixed local scanner invocation where that path is affected.
  Supported inventory matching is distinct from probing hosts or networks.
- Artifact downloads must stay within the intended artifact roots, including
  traversal and symlink cases. Workflow errors and exports can leak paths,
  credentials, provider payloads, or project data even without public hosting.
- Check the actual listener, proxy, credential, and user topology when exposure
  changes. A local-only assumption cannot establish safety for a shared service.
- Database migrations and recovery paths need evidence that the intended data
  survives; a successful process exit is not a restore verification.

An explicit user request establishes the requested scope. Ask only about missing
deployment facts that materially affect the work. Report the tested boundary
and residual uncertainty; do not infer certification from a generic green gate.
