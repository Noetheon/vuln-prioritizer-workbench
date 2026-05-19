import { VpwGrid, VpwPanel, VpwSectionHeader } from "@/components/vpw"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"
import { WaiversWorkbenchCreateGuidance } from "./WaiversWorkbenchCreateGuidance"
import { WaiverForm } from "./WaiversWorkbenchForm"

export function CreateWaiverSection({
  completeness,
  onCreateWaiver,
  onFieldChange,
  projectListLoading,
  projectSummary,
  projects,
  reviewDue,
  selectedProject,
  waiverActionLoading,
  waiverForm,
}: Pick<
  WaiversWorkbenchProps,
  | "onCreateWaiver"
  | "onFieldChange"
  | "projectListLoading"
  | "projectSummary"
  | "projects"
  | "selectedProject"
  | "waiverActionLoading"
  | "waiverForm"
> & {
  completeness: number
  reviewDue: string
}) {
  return (
    <VpwGrid columns={2}>
      <div id="create-waiver">
        <VpwPanel className="flex flex-col gap-5 p-5">
          <VpwSectionHeader
            description="Create an accepted-risk decision only when remediation cannot happen immediately."
            eyebrow="Governance form"
            title="Create waiver"
          />
          <WaiverForm
            buttonLabel="Create waiver"
            onFieldChange={onFieldChange}
            onSubmit={onCreateWaiver}
            waiverActionLoading={
              waiverActionLoading || projectListLoading || projects.length === 0
            }
            waiverForm={waiverForm}
          />
        </VpwPanel>
      </div>

      <WaiversWorkbenchCreateGuidance
        completeness={completeness}
        projectSummary={projectSummary}
        reviewDue={reviewDue}
        selectedProject={selectedProject}
      />
    </VpwGrid>
  )
}
