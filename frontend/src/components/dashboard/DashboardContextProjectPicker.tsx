import type { ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

type DashboardContextProjectPickerProps = {
  effectiveProjects: readonly ProjectPublic[]
  onProjectChange: (projectId: string) => void
  projectListLoading: boolean
  selectedProjectId: string
}

export function DashboardContextProjectPicker({
  effectiveProjects,
  onProjectChange,
  projectListLoading,
  selectedProjectId,
}: DashboardContextProjectPickerProps) {
  return (
    <Select
      disabled={projectListLoading || effectiveProjects.length === 0}
      onValueChange={(value) => {
        if (value !== "none") onProjectChange(value)
      }}
      value={selectedProjectId || "none"}
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
