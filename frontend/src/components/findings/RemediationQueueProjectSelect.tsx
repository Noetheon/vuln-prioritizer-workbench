import type { ProjectPublic } from "@/api-client"
import { VpwField, VpwSelectControl } from "@/components/vpw"

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
    <VpwField className="vpw-filter-field vpw-filter-field--md" label="Project">
      <VpwSelectControl
        ariaLabel="Project"
        disabled={projectListLoading || projects.length === 0}
        onValueChange={onProjectChange}
        options={projects.map((project) => ({
          label: project.name,
          value: project.id,
        }))}
        placeholder="No projects"
        value={selectedProjectId}
      />
    </VpwField>
  )
}
