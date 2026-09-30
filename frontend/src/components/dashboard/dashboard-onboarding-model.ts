import type { ProjectOnboardingPublic } from "../../api-client"

export type OnboardingStepId = "project" | "import" | "context" | "report"

export type OnboardingStep = {
  description: string
  detail: string | null
  done: boolean
  id: OnboardingStepId
  title: string
}

function plural(count: number, noun: string) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`
}

/** The four first-setup steps, with what is already done for this project. */
export function buildOnboardingSteps({
  onboarding,
  projectName,
}: {
  onboarding: ProjectOnboardingPublic | null
  projectName: string | null
}): OnboardingStep[] {
  const imports = onboarding?.import_count ?? 0
  const findings = onboarding?.finding_count ?? 0
  const assets = onboarding?.asset_count ?? 0
  const withContext = onboarding?.assets_with_context ?? 0
  const reports = onboarding?.report_count ?? 0
  return [
    {
      description:
        "A project holds one application, service, environment, or assessment.",
      detail: projectName,
      done: Boolean(projectName),
      id: "project",
      title: "Create a project",
    },
    {
      description:
        "Upload a Trivy or Grype report, an SBOM, or a CVE list. The first import fetches NVD, EPSS, and KEV.",
      detail:
        imports > 0
          ? `${plural(findings, "finding")} from ${plural(imports, "import")}`
          : null,
      done: imports > 0,
      id: "import",
      title: "Import scanner findings",
    },
    {
      description:
        "Set exposure, criticality, and owners, so scores reflect where each finding runs.",
      detail:
        withContext > 0
          ? `${withContext} of ${plural(assets, "asset")} have context`
          : null,
      done: withContext > 0,
      id: "context",
      title: "Add asset context",
    },
    {
      description:
        "Record the project state as an executive report, a technical report, or a verifiable evidence ZIP.",
      detail: reports > 0 ? plural(reports, "report") : null,
      done: reports > 0,
      id: "report",
      title: "Generate the first report",
    },
  ]
}

/** The step to do next: the first one not done yet. */
export function nextOnboardingStep(
  steps: readonly OnboardingStep[],
): OnboardingStep | null {
  return steps.find((step) => !step.done) ?? null
}

/**
 * Show the checklist until the selected project has its first report.
 * Without any project it always shows; while loading it waits.
 */
export function onboardingVisible({
  hasProjects,
  onboarding,
  selectedProjectId,
}: {
  hasProjects: boolean
  onboarding: ProjectOnboardingPublic | null
  selectedProjectId: string
}) {
  if (!hasProjects) {
    return true
  }
  if (!selectedProjectId || onboarding === null) {
    return false
  }
  return onboarding.project_id === selectedProjectId && !onboarding.complete
}
