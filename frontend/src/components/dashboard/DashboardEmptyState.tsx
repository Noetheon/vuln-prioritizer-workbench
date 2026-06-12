import { Link } from "@/lib/router"
import { DatabaseZap, Import, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { VpwSurface } from "@/components/vpw"

type DemoWorkspaceActionProps = {
  demoWorkspacePending: boolean
  onLoadDemoWorkspace: () => void
}

type DashboardSetupEmptyStateProps = DemoWorkspaceActionProps & {
  demoWorkspaceEnabled: boolean
}

export function DashboardSetupEmptyState({
  demoWorkspaceEnabled,
  demoWorkspacePending,
  onLoadDemoWorkspace,
}: DashboardSetupEmptyStateProps) {
  return (
    <VpwSurface
      aria-label="No project selected - getting started"
      className="border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-8 py-10"
    >
      <div className="mx-auto max-w-lg">
        <div className="flex flex-col items-center text-center">
          <div className="mb-4 flex size-14 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-navy)]">
            <ShieldCheck className="size-7 text-[var(--vpw-amber)]" />
          </div>
          <h3 className="text-lg font-semibold text-[var(--vpw-text-primary)]">
            Set up Risk Operations
          </h3>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            Select a project, import findings, and run analysis to activate the
            full Risk Operations cockpit.
          </p>
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            <Button asChild size="sm">
              <Link to="/imports">
                <Import aria-hidden="true" className="size-4" />
                Import findings
              </Link>
            </Button>
            {demoWorkspaceEnabled ? (
              <Button
                disabled={demoWorkspacePending}
                onClick={onLoadDemoWorkspace}
                size="sm"
                type="button"
                variant="outline"
              >
                <DatabaseZap aria-hidden="true" className="size-4" />
                {demoWorkspacePending
                  ? "Preparing demo"
                  : "Load demo workspace"}
              </Button>
            ) : null}
            <Button asChild size="sm" variant="outline">
              <Link to="/projects">View projects</Link>
            </Button>
          </div>
        </div>
        <div
          aria-hidden="true"
          className="my-6 h-px bg-[var(--vpw-border-subtle)]"
        />
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              1
            </div>
            <p className="text-xs font-medium text-[var(--vpw-text-secondary)]">
              Select or create a project
            </p>
          </div>
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              2
            </div>
            <p className="text-xs font-medium text-[var(--vpw-text-secondary)]">
              Import scanner findings
            </p>
          </div>
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              3
            </div>
            <p className="text-xs font-medium text-[var(--vpw-text-secondary)]">
              Run analysis to prioritize
            </p>
          </div>
        </div>
      </div>
    </VpwSurface>
  )
}
