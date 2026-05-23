import type { ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { DEMO_PROJECT_ID } from "@/lib/demo-data"

type DashboardContextProjectPickerProps = {
  effectiveProjects: readonly ProjectPublic[]
  isDemoMode: boolean
  onProjectChange: (projectId: string) => void
  projectListLoading: boolean
  selectedProjectId: string
}

export function DashboardContextProjectPicker({
  effectiveProjects,
  isDemoMode,
  onProjectChange,
  projectListLoading,
  selectedProjectId,
}: DashboardContextProjectPickerProps) {
  return (
    <Select
      disabled={isDemoMode || projectListLoading || effectiveProjects.length === 0}
      onValueChange={(value) => {
        if (value !== "none") onProjectChange(value)
      }}
      value={isDemoMode ? DEMO_PROJECT_ID : selectedProjectId || "none"}
    >
      <SelectTrigger
        aria-label="Dashboard project"
        className="w-full min-w-0 bg-[var(--vpw-bg-card)] sm:w-72"
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
  )
}
