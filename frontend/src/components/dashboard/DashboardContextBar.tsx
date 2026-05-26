import type { ProjectPublic, ProviderStatusPublic } from "@/api-client"
import { VpwCommandPanel } from "@/components/vpw"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { DashboardContextActions } from "./DashboardContextActions"
import { DashboardContextProjectPicker } from "./DashboardContextProjectPicker"

type DashboardContextBarProps = {
  effectiveProjects: readonly ProjectPublic[]
  effectiveProviderStatus: ProviderStatusPublic | null
  effectiveSelectedProject: ProjectPublic | null
  freshness: ProviderFreshnessSummary
  demoWorkspaceEnabled: boolean
  demoWorkspacePending: boolean
  isManagedDemoWorkspace: boolean
  onLoadDemoWorkspace: () => void
  onProjectChange: (projectId: string) => void
  onRefresh: () => void
  onResetDemoWorkspace: () => void
  projectListLoading: boolean
  providerStatusLoading: boolean
  selectedProjectId: string
}

export function DashboardContextBar({
  effectiveProjects,
  effectiveProviderStatus,
  effectiveSelectedProject,
  freshness,
  demoWorkspaceEnabled,
  demoWorkspacePending,
  isManagedDemoWorkspace,
  onLoadDemoWorkspace,
  onProjectChange,
  onRefresh,
  onResetDemoWorkspace,
  projectListLoading,
  providerStatusLoading,
  selectedProjectId,
}: DashboardContextBarProps) {
  return (
    <VpwCommandPanel
      actions={
        <DashboardContextProjectPicker
          effectiveProjects={effectiveProjects}
          onProjectChange={onProjectChange}
          projectListLoading={projectListLoading}
          selectedProjectId={selectedProjectId}
        />
      }
      className="dashboard-context-bar"
      description="Prioritized vulnerability operations for this project."
      eyebrow="Security Operations"
      title={
        effectiveSelectedProject
          ? effectiveSelectedProject.name
          : "No project selected"
      }
    >
      <DashboardContextActions
        demoWorkspaceEnabled={demoWorkspaceEnabled}
        demoWorkspacePending={demoWorkspacePending}
        effectiveProviderStatus={effectiveProviderStatus}
        freshness={freshness}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />
    </VpwCommandPanel>
  )
}
