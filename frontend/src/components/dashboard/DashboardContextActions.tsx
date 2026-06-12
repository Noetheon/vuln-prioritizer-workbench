import { Link } from "@/lib/router"
import { BellRing, DatabaseZap, Import, RefreshCw, RotateCcw } from "lucide-react"
import type { ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { ProviderStatusBadge } from "../risk/ProviderStatusBadge"

type DashboardContextActionsProps = {
  demoWorkspaceEnabled: boolean
  demoWorkspacePending: boolean
  effectiveProviderStatus: ProviderStatusPublic | null
  freshness: ProviderFreshnessSummary
  isManagedDemoWorkspace: boolean
  onLoadDemoWorkspace: () => void
  onRefresh: () => void
  onResetDemoWorkspace: () => void
  providerStatusLoading: boolean
  selectedProjectId: string
}

export function DashboardContextActions({
  demoWorkspaceEnabled,
  demoWorkspacePending,
  effectiveProviderStatus,
  freshness,
  isManagedDemoWorkspace,
  onLoadDemoWorkspace,
  onRefresh,
  onResetDemoWorkspace,
  providerStatusLoading,
  selectedProjectId,
}: DashboardContextActionsProps) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const canLoadDemoWorkspace =
    demoWorkspaceEnabled && !isManagedDemoWorkspace && selectedProjectId !== ""

  return (
    <div className="dashboard-context-actions flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <ProviderStatusBadge
          status={
            effectiveProviderStatus?.status ??
            (providerStatusLoading ? "loading" : "unknown")
          }
        />
        <span className="text-sm text-[var(--vpw-text-secondary)]">
          {freshness.value}
        </span>
        <span className="text-[var(--vpw-text-muted)]">/</span>
        <span className="text-xs text-[var(--vpw-text-muted)]">
          {freshness.detail}
        </span>
      </div>

      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center xl:justify-end">
        <Button
          asChild
          className="w-full justify-center font-semibold sm:w-auto"
        >
          <Link search={projectSearch} to="/imports">
            <Import aria-hidden="true" data-icon="inline-start" />
            Import findings
          </Link>
        </Button>
        <Button
          asChild
          className="w-full justify-center sm:w-auto"
          variant="outline"
        >
          <Link search={projectSearch} to="/reports">
            <BellRing aria-hidden="true" data-icon="inline-start" />
            Generate evidence
          </Link>
        </Button>
        {isManagedDemoWorkspace ? (
          <Button
            className="w-full justify-center sm:w-auto"
            disabled={demoWorkspacePending}
            onClick={onResetDemoWorkspace}
            type="button"
            variant="outline"
          >
            <RotateCcw aria-hidden="true" data-icon="inline-start" />
            {demoWorkspacePending ? "Preparing demo" : "Reset demo"}
          </Button>
        ) : null}
        {canLoadDemoWorkspace ? (
          <Button
            className="w-full justify-center sm:w-auto"
            disabled={demoWorkspacePending}
            onClick={onLoadDemoWorkspace}
            type="button"
            variant="outline"
          >
            <DatabaseZap aria-hidden="true" data-icon="inline-start" />
            {demoWorkspacePending ? "Preparing demo" : "Load demo workspace"}
          </Button>
        ) : null}
        <Button
          aria-label="Refresh dashboard"
          className="w-full justify-center sm:w-auto"
          onClick={onRefresh}
          size="sm"
          type="button"
          variant="outline"
        >
          <RefreshCw aria-hidden="true" data-icon="inline-start" />
          Refresh
        </Button>
      </div>
    </div>
  )
}
