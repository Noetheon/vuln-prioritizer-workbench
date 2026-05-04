import { Link } from "@tanstack/react-router"
import { Import, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { VpwSurface } from "@/components/vpw"

export function DashboardDemoBanner() {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
      <ShieldCheck
        aria-hidden="true"
        className="size-4 shrink-0 text-amber-600"
      />
      <p>
        <strong className="font-semibold">Demo preview</strong> — sample data
        from a fictional payments service. Connect a real project to see live
        metrics.
      </p>
      <Button asChild className="ml-auto shrink-0" size="sm" variant="outline">
        <Link to="/projects">Add project</Link>
      </Button>
    </div>
  )
}

export function DashboardSetupEmptyState() {
  return (
    <VpwSurface
      aria-label="No project selected — getting started"
      className="border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-8 py-10"
    >
      <div className="mx-auto max-w-lg">
        <div className="flex flex-col items-center text-center">
          <div className="mb-4 flex size-14 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-navy)] shadow-[var(--vpw-shadow-2)]">
            <ShieldCheck className="size-7 text-[var(--vpw-amber)]" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900">
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
            <Button asChild size="sm" variant="outline">
              <Link to="/projects">View projects</Link>
            </Button>
          </div>
        </div>
        <hr className="my-6 border-slate-200" />
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              1
            </div>
            <p className="text-xs font-medium text-slate-700">
              Select or create a project
            </p>
          </div>
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              2
            </div>
            <p className="text-xs font-medium text-slate-700">
              Import scanner findings
            </p>
          </div>
          <div>
            <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
              3
            </div>
            <p className="text-xs font-medium text-slate-700">
              Run analysis to prioritize
            </p>
          </div>
        </div>
      </div>
    </VpwSurface>
  )
}
