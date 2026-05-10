import { Link } from "@tanstack/react-router"
import { BellRing, Import, RefreshCw, ShieldCheck } from "lucide-react"
import type { ProjectPublic, ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { DEMO_PROJECT_ID } from "@/lib/demo-data"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { ProviderStatusBadge } from "../risk/ProviderStatusBadge"

type DashboardHeroProps = {
  effectiveProjects: readonly ProjectPublic[]
  effectiveProviderStatus: ProviderStatusPublic | null
  effectiveSelectedProject: ProjectPublic | null
  freshness: ProviderFreshnessSummary
  isDemoMode: boolean
  onProjectChange: (projectId: string) => void
  onRefresh: () => void
  projectListLoading: boolean
  providerStatusLoading: boolean
  selectedProjectId: string
}

export function DashboardHero({
  effectiveProjects,
  effectiveProviderStatus,
  effectiveSelectedProject,
  freshness,
  isDemoMode,
  onProjectChange,
  onRefresh,
  projectListLoading,
  providerStatusLoading,
  selectedProjectId,
}: DashboardHeroProps) {
  return (
    <div className="relative overflow-hidden rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-strong)] bg-[var(--vpw-navy)] px-5 py-4 shadow-[var(--vpw-shadow-2)]">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "radial-gradient(circle at 1px 1px, white 1px, transparent 0)",
          backgroundSize: "24px 24px",
        }}
      />
      <div className="relative flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <ShieldCheck
              aria-hidden="true"
              className="size-3.5 text-[var(--vpw-amber)]"
            />
            <span className="text-[10px] font-bold uppercase text-[var(--vpw-amber)]">
              Security Operations
            </span>
          </div>
          <p className="truncate text-base font-semibold text-white">
            {effectiveSelectedProject
              ? effectiveSelectedProject.name
              : "No project selected"}
          </p>
          <p className="mt-0.5 text-xs text-white/60">
            Prioritized vulnerability operations for this project
          </p>
        </div>

        <div className="flex w-full min-w-0 flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center sm:justify-end">
          <Select
            disabled={
              isDemoMode || projectListLoading || effectiveProjects.length === 0
            }
            onValueChange={(value) => {
              if (value !== "none") onProjectChange(value)
            }}
            value={isDemoMode ? DEMO_PROJECT_ID : selectedProjectId || "none"}
          >
            <SelectTrigger
              aria-label="Dashboard project"
              className="w-full min-w-0 border-white/20 bg-white/10 text-white hover:bg-white/20 focus:ring-white/30 sm:w-64 xl:w-72"
            >
              <SelectValue placeholder="Select project" />
            </SelectTrigger>
            <SelectContent>
              {effectiveProjects.length === 0 ? (
                <SelectItem value="none">No projects yet</SelectItem>
              ) : (
                effectiveProjects.map((project) => (
                  <SelectItem key={project.id} value={project.id}>
                    {project.name}
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>

          <Button
            asChild
            className="w-full justify-center bg-white font-semibold text-[var(--vpw-navy)] hover:bg-white/90 sm:w-auto"
          >
            <Link to="/imports">
              <Import aria-hidden="true" data-icon="inline-start" />
              Import findings
            </Link>
          </Button>
          <Button
            asChild
            className="w-full justify-center border border-white/25 bg-transparent text-white hover:bg-white/10 hover:text-white sm:w-auto"
            variant="ghost"
          >
            <Link to="/reports">
              <BellRing aria-hidden="true" data-icon="inline-start" />
              Generate evidence
            </Link>
          </Button>
          <Button
            aria-label="Refresh dashboard"
            className="self-end text-white/70 hover:bg-white/10 hover:text-white sm:self-auto"
            onClick={onRefresh}
            size="icon"
            type="button"
            variant="ghost"
          >
            <RefreshCw aria-hidden="true" />
          </Button>
        </div>
      </div>

      <div className="relative mt-3 flex flex-wrap items-center gap-3 border-t border-white/10 pt-3">
        <ProviderStatusBadge
          status={
            effectiveProviderStatus?.status ??
            (providerStatusLoading ? "loading" : "unknown")
          }
        />
        <span className="text-sm text-white/75">{freshness.value}</span>
        <span className="text-white/35">·</span>
        <span className="text-xs text-white/60">{freshness.detail}</span>
      </div>
    </div>
  )
}
