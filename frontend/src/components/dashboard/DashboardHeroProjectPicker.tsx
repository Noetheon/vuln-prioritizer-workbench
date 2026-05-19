import { ShieldCheck } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { DEMO_PROJECT_ID } from "@/lib/demo-data"

type DashboardHeroProjectPickerProps = {
  effectiveProjects: readonly ProjectPublic[]
  effectiveSelectedProject: ProjectPublic | null
  isDemoMode: boolean
  onProjectChange: (projectId: string) => void
  projectListLoading: boolean
  selectedProjectId: string
}

export function DashboardHeroProjectPicker({
  effectiveProjects,
  effectiveSelectedProject,
  isDemoMode,
  onProjectChange,
  projectListLoading,
  selectedProjectId,
}: DashboardHeroProjectPickerProps) {
  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="min-w-0">
        <div className="flex items-center gap-2 mb-1.5">
          <ShieldCheck
            aria-hidden="true"
            className="size-3.5 text-[var(--vpw-teal)]"
          />
          <span className="text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
            Security Operations
          </span>
        </div>
        <p className="break-words text-base font-semibold text-[var(--vpw-text-primary)]">
          {effectiveSelectedProject
            ? effectiveSelectedProject.name
            : "No project selected"}
        </p>
        <p className="mt-0.5 text-xs text-[var(--vpw-text-muted)]">
          Prioritized vulnerability operations for this project
        </p>
      </div>

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
          className="w-full min-w-0 bg-[var(--vpw-bg-card)] lg:w-72"
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
    </div>
  )
}
