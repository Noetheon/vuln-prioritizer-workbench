import type { ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

type RemediationQueueProjectSelectProps = {
  onProjectChange: (id: string) => void
  projectListLoading: boolean
  projects: ProjectPublic[]
  selectedProjectId: string
}

export function RemediationQueueProjectSelect({
  onProjectChange,
  projectListLoading,
  projects,
  selectedProjectId,
}: RemediationQueueProjectSelectProps) {
  return (
    <div className="flex min-w-44 flex-col gap-1">
      <span className="text-[11px] font-semibold uppercase text-muted-foreground">
        Project
      </span>
      <Select
        disabled={projectListLoading || projects.length === 0}
        onValueChange={onProjectChange}
        value={selectedProjectId}
      >
        <SelectTrigger aria-label="Project" className="h-10 w-48 text-sm">
          <SelectValue placeholder="No projects" />
        </SelectTrigger>
        <SelectContent>
          {projects.map((project) => (
            <SelectItem key={project.id} value={project.id}>
              {project.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
