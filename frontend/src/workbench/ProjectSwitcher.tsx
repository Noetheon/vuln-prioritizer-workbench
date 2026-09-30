import { FolderKanban } from "lucide-react"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useWorkbenchContext } from "./WorkbenchContext"

/** The one place to change the active project, in the page header. */
export function ProjectSwitcher() {
  const { projectListLoading, projects, selectedProjectId, switchProject } =
    useWorkbenchContext()
  // Without projects the Overview's setup checklist offers "Create project".
  if (!projectListLoading && projects.length === 0) {
    return null
  }
  return (
    <Select
      disabled={projectListLoading}
      onValueChange={(projectId) => {
        if (projectId !== selectedProjectId) switchProject(projectId)
      }}
      // An empty value shows the placeholder while projects load.
      value={selectedProjectId}
    >
      <SelectTrigger
        aria-label="Project"
        className="h-9 w-full min-w-0 bg-[var(--vpw-bg-card)] sm:w-64"
      >
        <FolderKanban
          aria-hidden="true"
          className="size-4 shrink-0 text-[var(--vpw-text-muted)]"
        />
        <SelectValue placeholder="Select project" />
      </SelectTrigger>
      <SelectContent align="end">
        {projects.map((project) => (
          <SelectItem key={project.id} value={project.id}>
            {project.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
