import type { AnalysisRunPublic, ProjectPublic } from "@/api-client"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  CURRENT_PROJECT_STATE,
  isReportableRun,
  reportRunOptionLabel,
} from "./report-run-scope-model"

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
        aria-label="Report run"
        className="h-10 w-full min-w-0 sm:w-80"
      >
        <SelectValue placeholder="Select import run" />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          {runs.length === 0 ? (
            <SelectItem disabled value="none">
              No runs available
            </SelectItem>
          ) : (
            <SelectItem value={CURRENT_PROJECT_STATE}>
              Current project state · all findings
            </SelectItem>
          )}
          {runs.map((run) => (
            <SelectItem
              disabled={!isReportableRun(run)}
              key={run.id}
              value={run.id}
            >
              {reportRunOptionLabel(run)}
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}
