import type { ProjectPublic, ProviderStatusPublic } from "@/api-client"
import { VpwCommandPanel } from "@/components/vpw"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { DashboardContextActions } from "./DashboardContextActions"

type DashboardContextBarProps = {
  demoWorkspaceEnabled: boolean
  demoWorkspacePending: boolean
  effectiveProjects: readonly ProjectPublic[]
  effectiveProviderStatus: ProviderStatusPublic | null
  effectiveSelectedProject: ProjectPublic | null
  freshness: ProviderFreshnessSummary
  hasFindings: boolean
  isManagedDemoWorkspace: boolean
  onCreateProject: () => void
  onLoadDemoWorkspace: () => void
  onRefresh: () => void
  onResetDemoWorkspace: () => void
  providerStatusLoading: boolean
  selectedProjectId: string
}

export function DashboardContextBar({
  demoWorkspaceEnabled,
  demoWorkspacePending,
  effectiveProjects,
  effectiveProviderStatus,
  effectiveSelectedProject,
  freshness,
  hasFindings,
  isManagedDemoWorkspace,
  onCreateProject,
  onLoadDemoWorkspace,
  onRefresh,
  onResetDemoWorkspace,
  providerStatusLoading,
  selectedProjectId,
}: DashboardContextBarProps) {
  return (
    <VpwCommandPanel
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
        hasFindings={hasFindings}
        hasProjects={effectiveProjects.length > 0}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        onCreateProject={onCreateProject}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />
    </VpwCommandPanel>
  )
}
