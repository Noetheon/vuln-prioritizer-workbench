import { Link } from "@/lib/router"
import { CheckCircle2, DatabaseZap, FolderPlus } from "lucide-react"
import type { ProjectOnboardingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  buildOnboardingSteps,
  nextOnboardingStep,
  type OnboardingStep,
} from "./dashboard-onboarding-model"

type DashboardOnboardingChecklistProps = {
  demoWorkspaceEnabled: boolean
  demoWorkspacePending: boolean
  onCreateProject: () => void
  onLoadDemoWorkspace: () => void
  onboarding: ProjectOnboardingPublic | null
  projectName: string | null
  selectedProjectId: string
}

export function DashboardOnboardingChecklist({
  demoWorkspaceEnabled,
  demoWorkspacePending,
  onCreateProject,
  onLoadDemoWorkspace,
  onboarding,
  projectName,
  selectedProjectId,
}: DashboardOnboardingChecklistProps) {
  const steps = buildOnboardingSteps({ onboarding, projectName })
  const next = nextOnboardingStep(steps)
  const doneCount = steps.filter((step) => step.done).length

  return (
    <section
      aria-labelledby="dashboard-onboarding-title"
      className="dashboard-onboarding"
    >
      <div className="dashboard-onboarding-head">
        <p className="dashboard-onboarding-eyebrow">Get started</p>
        <h2 id="dashboard-onboarding-title">
          {projectName ? `Set up ${projectName}` : "Set up your first project"}
        </h2>
        <p className="dashboard-onboarding-lede">
          {doneCount} of {steps.length} steps done. This checklist stays here
          until the project has its first report.
        </p>
        <div
          aria-label={`${doneCount} of ${steps.length} setup steps done`}
          aria-valuemax={steps.length}
          aria-valuemin={0}
          aria-valuenow={doneCount}
          className="dashboard-onboarding-progress"
          role="progressbar"
        >
          <span
            className="dashboard-onboarding-progress-fill"
            style={{ width: `${(doneCount / steps.length) * 100}%` }}
          />
        </div>
      </div>
      <ol className="dashboard-onboarding-steps">
        {steps.map((step, index) => (
          <li
            className="dashboard-onboarding-step"
            data-state={
              step.done ? "done" : step.id === next?.id ? "next" : "todo"
            }
            key={step.id}
          >
            <span aria-hidden="true" className="dashboard-onboarding-marker">
              {step.done ? <CheckCircle2 className="size-4" /> : index + 1}
            </span>
            <div className="dashboard-onboarding-copy">
              <h3>
                {step.title}
                {step.done ? <span className="sr-only"> (done)</span> : null}
              </h3>
              <p>{step.done && step.detail ? step.detail : step.description}</p>
            </div>
            {step.done ? null : (
              <OnboardingAction
                hasFindings={(onboarding?.finding_count ?? 0) > 0}
                isNext={step.id === next?.id}
                onCreateProject={onCreateProject}
                projectSelected={Boolean(selectedProjectId)}
                selectedProjectId={selectedProjectId}
                step={step}
              />
            )}
          </li>
        ))}
      </ol>
      {demoWorkspaceEnabled && !projectName ? (
        <div className="dashboard-onboarding-foot">
          <span>Want to look around first?</span>
          <Button
            disabled={demoWorkspacePending}
            onClick={onLoadDemoWorkspace}
            size="sm"
            type="button"
            variant="outline"
          >
            <DatabaseZap aria-hidden="true" className="size-4" />
            {demoWorkspacePending ? "Preparing demo" : "Load demo workspace"}
          </Button>
        </div>
      ) : null}
    </section>
  )
}

function OnboardingAction({
  hasFindings,
  isNext,
  onCreateProject,
  projectSelected,
  selectedProjectId,
  step,
}: {
  hasFindings: boolean
  isNext: boolean
  onCreateProject: () => void
  projectSelected: boolean
  selectedProjectId: string
  step: OnboardingStep
}) {
  const variant = isNext ? "default" : "outline"
  if (step.id === "project") {
    return (
      <Button onClick={onCreateProject} size="sm" type="button" variant={variant}>
        <FolderPlus aria-hidden="true" className="size-4" />
        Create project
      </Button>
    )
  }
  // A report needs findings to cover.
  if (!projectSelected || (step.id === "report" && !hasFindings)) {
    return null
  }
  const search = selectedProjectRouteSearch(selectedProjectId)
  const target = {
    context: { label: "Review assets", to: "/assets" },
    import: { label: "Import findings", to: "/imports/new" },
    report: { label: "Generate evidence", to: "/evidence" },
  } as const
  const { label, to } = target[step.id]
  return (
    <Button asChild size="sm" variant={variant}>
      <Link search={search} to={to}>
        {label}
      </Link>
    </Button>
  )
}
