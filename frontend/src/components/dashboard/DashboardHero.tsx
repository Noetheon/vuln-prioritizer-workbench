import type { ProjectPublic, ProviderStatusPublic } from "@/api-client"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { DashboardHeroActions } from "./DashboardHeroActions"
import { DashboardHeroProjectPicker } from "./DashboardHeroProjectPicker"

type DashboardHeroProps = {
  effectiveProjects: readonly ProjectPublic[]
  effectiveProviderStatus: ProviderStatusPublic | null
  effectiveSelectedProject: ProjectPublic | null
  freshness: ProviderFreshnessSummary
  demoWorkspaceEnabled: boolean
  demoWorkspacePending: boolean
  isManagedDemoWorkspace: boolean
  isDemoMode: boolean
  onLoadDemoWorkspace: () => void
  onProjectChange: (projectId: string) => void
  onRefresh: () => void
  onResetDemoWorkspace: () => void
  projectListLoading: boolean
  providerStatusLoading: boolean
  selectedProjectId: string
}

export function DashboardHero({
  effectiveProjects,
  effectiveProviderStatus,
  effectiveSelectedProject,
  freshness,
  demoWorkspaceEnabled,
  demoWorkspacePending,
  isManagedDemoWorkspace,
  isDemoMode,
  onLoadDemoWorkspace,
  onProjectChange,
  onRefresh,
  onResetDemoWorkspace,
  projectListLoading,
  providerStatusLoading,
  selectedProjectId,
}: DashboardHeroProps) {
  return (
    <div className="dashboard-analyst-hero">
      <DashboardHeroProjectPicker
        effectiveProjects={effectiveProjects}
        effectiveSelectedProject={effectiveSelectedProject}
        isDemoMode={isDemoMode}
        onProjectChange={onProjectChange}
        projectListLoading={projectListLoading}
        selectedProjectId={selectedProjectId}
      />
      <DashboardHeroActions
        demoWorkspaceEnabled={demoWorkspaceEnabled}
        demoWorkspacePending={demoWorkspacePending}
        effectiveProviderStatus={effectiveProviderStatus}
        freshness={freshness}
        isDemoMode={isDemoMode}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />
    </div>
  )
}
