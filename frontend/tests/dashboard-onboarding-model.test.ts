import assert from "node:assert/strict"
import test from "node:test"

import type { ProjectOnboardingPublic } from "../src/api-client"
import {
  buildOnboardingSteps,
  nextOnboardingStep,
  onboardingVisible,
} from "../src/components/dashboard/dashboard-onboarding-model.ts"

function onboarding(
  overrides: Partial<ProjectOnboardingPublic> = {},
): ProjectOnboardingPublic {
  return {
    asset_count: 0,
    assets_with_context: 0,
    complete: false,
    finding_count: 0,
    import_count: 0,
    project_id: "project-1",
    report_count: 0,
    ...overrides,
  }
}

test("a fresh install starts with creating a project", () => {
  const steps = buildOnboardingSteps({ onboarding: null, projectName: null })
  assert.deepEqual(
    steps.map((step) => [step.id, step.done]),
    [
      ["project", false],
      ["import", false],
      ["context", false],
      ["report", false],
    ],
  )
  assert.equal(nextOnboardingStep(steps)?.id, "project")
  assert.equal(
    onboardingVisible({ hasProjects: false, onboarding: null, selectedProjectId: "" }),
    true,
  )
})

test("steps fill in as the project gets data", () => {
  const steps = buildOnboardingSteps({
    onboarding: onboarding({
      asset_count: 3,
      assets_with_context: 1,
      finding_count: 12,
      import_count: 1,
    }),
    projectName: "Payments",
  })
  assert.equal(steps[0].detail, "Payments")
  assert.equal(steps[1].detail, "12 findings from 1 import")
  assert.equal(steps[2].detail, "1 of 3 assets have context")
  assert.equal(steps[3].done, false)
  assert.equal(nextOnboardingStep(steps)?.id, "report")

  const single = buildOnboardingSteps({
    onboarding: onboarding({ finding_count: 1, import_count: 2, report_count: 1 }),
    projectName: "Payments",
  })
  assert.equal(single[1].detail, "1 finding from 2 imports")
  assert.equal(single[2].detail, null)
  assert.equal(single[3].detail, "1 report")
})

test("the checklist stays until the first report exists", () => {
  const selected = { hasProjects: true, selectedProjectId: "project-1" }
  assert.equal(onboardingVisible({ ...selected, onboarding: null }), false)
  assert.equal(onboardingVisible({ ...selected, onboarding: onboarding() }), true)
  assert.equal(
    onboardingVisible({
      ...selected,
      onboarding: onboarding({ complete: true, report_count: 1 }),
    }),
    false,
  )
  // Data for another project never decides.
  assert.equal(
    onboardingVisible({
      ...selected,
      onboarding: onboarding({ project_id: "project-2" }),
    }),
    false,
  )
  assert.equal(
    onboardingVisible({ hasProjects: true, onboarding: onboarding(), selectedProjectId: "" }),
    false,
  )
  assert.equal(
    nextOnboardingStep(
      buildOnboardingSteps({
        onboarding: onboarding({
          assets_with_context: 1,
          import_count: 1,
          report_count: 1,
        }),
        projectName: "Payments",
      }),
    ),
    null,
  )
})
