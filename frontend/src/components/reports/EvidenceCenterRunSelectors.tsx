import type { AnalysisRunPublic, ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { runStatusLabel } from "@/lib/risk-format"
import { runFileLabel } from "./evidence-center-model"

type ReportProjectSelectProps = {
  disabled: boolean
  projects: ProjectPublic[]
  selectedProjectId: string
  onProjectChange: (id: string) => void
}

export function ReportProjectSelect({
  disabled,
  onProjectChange,
  projects,
  selectedProjectId,
}: ReportProjectSelectProps) {
  return (
    <Select
      disabled={disabled}
      onValueChange={onProjectChange}
      value={selectedProjectId}
    >
      <SelectTrigger
        aria-label="Reports project"
        className="h-10 w-full min-w-0 sm:w-56"
      >
        <SelectValue placeholder="Select project" />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          {projects.length === 0 ? (
            <SelectItem disabled value="none">
              No projects available
            </SelectItem>
          ) : null}
          {projects.map((project) => (
            <SelectItem key={project.id} value={project.id}>
              {project.name}
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}

type ReportRunSelectProps = {
  disabled: boolean
  runs: AnalysisRunPublic[]
  selectedRunId: string
  onRunIdChange: (id: string) => void
}

export function ReportRunSelect({
  disabled,
  onRunIdChange,
  runs,
  selectedRunId,
}: ReportRunSelectProps) {
  return (
    <Select
      disabled={disabled}
      onValueChange={onRunIdChange}
      value={selectedRunId}
    >
      <SelectTrigger
        aria-label="Select analysis run"
        className="h-10 w-full min-w-0 sm:w-64"
      >
        <SelectValue placeholder="Select analysis run" />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          {runs.length === 0 ? (
            <SelectItem disabled value="none">
              No runs available
            </SelectItem>
          ) : null}
          {runs.map((run) => (
            <SelectItem key={run.id} value={run.id}>
              {`${runStatusLabel(run.status)} - ${runFileLabel(run)} - ${run.id.slice(0, 8)}`}
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}
