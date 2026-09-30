# Continuous quality assurance

The test strategy is enforced by the required **quality-gate** check, source-bound
change records, independent health monitoring, and 90-day measurement retention.
Passing checks protect specified behavior; they cannot establish that every
requirement or test expectation is correct.

## Admission and releases

The Test quality workflow selects relevant contracts for each PR. Every matrix
job emits a receipt, including explicit "not required" decisions. The final job
runs after upstream failures and rejects missing/duplicate receipts, mismatched
selections, failed jobs, empty/skipped contracts, and evidence from another
repository, commit, run or attempt. After a failed campaign, rerun **all jobs**
so that execution attempts agree.

Add quality-gate to main's required checks after its first successful PR run.
Preserve existing checks, strict branch updates, administrator enforcement and
force-push/deletion restrictions. The read-only protection audit detects drift.

Release builds call the same workflow on the candidate commit and depend on its
success before creating artifacts. Older runs cannot authorize a new release.
Existing package, migration, browser and Docker release checks remain in place.

## Changes to the quality bar

The checker scripts/check_quality_policy.py identifies changes to execution,
coverage, mutation and performance policy, new public decision entry points,
removed Python regression cases, and added skip/xfail markers. The PR must include
a changed JSON record under quality/reviews/ covering the affected source hashes.
After adoption, the PR job runs the checker from the base branch: editing it
cannot silently relax its own current review requirement.

List obligations before writing a record:

    python scripts/check_quality_policy.py --base origin/main --describe

A vpw.quality-change.v1 record contains owner, reason, risk, validation,
coverage_impact, and a paths object mapping files to SHA-256 values (or "deleted").
Explain replaced requirements, comparative evidence and new coverage boundaries.
Refresh the record when affected source changes.

A record is author-supplied reasoning, not proof of independent human approval.
The maintainer reviews policy changes explicitly. A single-maintainer repository
cannot manufacture an independent reviewer; when another maintainer participates,
request a separate review for policy and decision semantics. Machine admission
also applies to administrators.

Every reproducible defect retains a minimal regression that fails before the fix
and passes after it, using independently specified expectations. If automation is
unsuitable, document the manual reproduction, reason, owner and follow-up.
Unstable tests require a repair deadline and tracking, not unlimited retries.
PR/bug templates and project guidance carry these requirements. New critical
entry points require an explicit example/property/mutation coverage decision.

## Exploration and retained measurements

PR properties remain deterministic. Scheduled and manually dispatched extended
campaigns vary their seed by execution identity and record the seed, Hypothesis
version and Python version. Replay with:

    VPW_PROPERTY_PROFILE=extended python -m pytest backend/tests/property --no-cov --hypothesis-seed=<recorded-seed>

Retain minimized failures as ordinary regressions; replay blobs are temporary
diagnostics tied to the tool version.

Detailed logs and public fixture artifacts expire after seven days. The compact
quality-metrics artifact retains receipts and trends for 90 days without user
databases or customer uploads. Baselines come only from successful main-branch
Test quality runs with verified repository/commit/run identity. Profiles, dataset
sizes, Python minor versions, operating systems, architectures and runner image
families are compared separately.

Initial runs report **calibrating**, not an invented baseline. Warnings cover
fewer checked tests/functions/mutations, a history metric reaching 90% of its
fixed budget, or more than 20% deterioration against an older three-run median
in each of three recent comparable runs. Fixed ceilings still block admission.
Warnings do not automatically loosen budgets; unavailable comparison data is
reported as **unavailable**. Review intentional scope/baseline changes with
evidence. Measurements describe these fixtures, not arbitrary production loads.

## Monitoring and response

Daily Quality health checks inspect Test quality, Maintenance and Provider Live
Drift on main. Disabled/missing/unreadable workflows, no successful full campaign
within ten days, the latest completed failure/cancellation, or a run stuck for
two hours require attention. Retained trend warnings and missing monitoring
artifacts also require attention. A newer successful campaign resolves an older
execution failure; an unrelated green check does not.

The workflow has contents/actions read permissions only. GitHub uses the account's
normal workflow notification settings. A separate daily Codex heartbeat checks
the same repository and branch protection, so disabling GitHub schedules does not
silence every observer. It reports meaningful changes, failures, recovery or
required action and stays quiet otherwise. Its availability still depends on the
Codex automation host.

The repository maintainer (@Noetheon, matching CODEOWNERS) owns triage. Classify
product regression, infrastructure/test failure or external provider/scanner
change; record tracking, repair owner and deadline. Completion requires the owning
contract on the repaired commit and affected recovery/release checks. Automation
never lowers thresholds, adds mutation equivalents or changes branch protection.

Read-only local verification:

    python -m scripts.check_quality_health --repository Noetheon/vuln-prioritizer-workbench --check-protection

See the [delivery record](architecture/quality-sustainability-delivery.md) for
verified local, hosted and activation outcomes.
