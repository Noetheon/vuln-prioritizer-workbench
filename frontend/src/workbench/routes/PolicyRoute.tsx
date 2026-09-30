import { FolderKanban, SlidersHorizontal } from "lucide-react"
import { ProjectPolicyCard } from "../../components/projects/ProjectPolicyCard"
import { Button } from "../../components/ui/button"
import {
  VpwCommandPanel,
  VpwEmptyState,
  VpwPageStack,
} from "../../components/vpw"
import { Link } from "../../lib/router"
import { useWorkbenchContext } from "../WorkbenchContext"

/** The project's priority thresholds and SLA targets, as their own page. */
export function PolicyRoute() {
  const { projectListLoading, selectedProject, selectedProjectId } =
    useWorkbenchContext()

  if (!selectedProjectId || !selectedProject) {
    return (
      <VpwPageStack>
        <VpwEmptyState
          action={
            projectListLoading ? null : (
              <Button asChild size="sm" variant="outline">
                <Link to="/projects">
                  <FolderKanban aria-hidden="true" className="size-4" />
                  Open projects
                </Link>
              </Button>
            )
          }
          ariaLabel="No project selected"
          description="Each project has its own priority policy. Select or create a project first."
          icon={<SlidersHorizontal aria-hidden="true" className="size-5" />}
          title={projectListLoading ? "Loading projects" : "No project selected"}
        />
      </VpwPageStack>
    )
  }

  return (
    <VpwPageStack>
      <VpwCommandPanel
        description="A finding is Critical when it is on the CISA KEV list, or when its EPSS and CVSS both reach the Critical thresholds; High and Medium need either one. Its SLA due date is the time the Workbench first saw it plus the SLA target of its priority. Saving a new version re-evaluates the project's findings."
        eyebrow="Priority policy"
        title={selectedProject.name}
      />
      <ProjectPolicyCard projectId={selectedProjectId} />
    </VpwPageStack>
  )
}
