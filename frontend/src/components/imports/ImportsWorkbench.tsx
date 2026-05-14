import { useState } from "react"
import { VpwStatusBanner } from "@/components/vpw"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import {
  ImportHero,
  ImportResult,
  ImportWizard,
  ParserErrors,
  RecentImports,
  SupportedFormats,
} from "./ImportsWorkbenchSections"

export function ImportsWorkbench(props: ImportsWorkbenchProps) {
  const hasProject = Boolean(props.selectedProjectId)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const [diagnosticsRunId, setDiagnosticsRunId] = useState("")

  function openDiagnostics(runId: string) {
    props.onSelectRun(runId)
    setDiagnosticsRunId(runId)
    setDiagnosticsOpen(true)
  }

  return (
    <div className="flex flex-col gap-6">
      <ImportHero
        importWizard={props.importWizard}
        projectListError={props.projectListError}
        projectRuns={props.projectRuns}
        providerStatus={props.providerStatus}
        selectedProject={props.selectedProject}
      />
      {props.projectListError ? (
        <VpwStatusBanner title="Projects unavailable" tone="critical">
          {props.projectListError}
        </VpwStatusBanner>
      ) : null}
      {!hasProject && !props.projectListLoading && !props.projectListError ? (
        <VpwStatusBanner title="Project required" tone="warning">
          Create or select a project before uploading import files.
        </VpwStatusBanner>
      ) : null}
      <ImportWizard {...props} />
      <SupportedFormats
        importWizard={props.importWizard}
        onInputTypeChange={props.onInputTypeChange}
        supportedFormats={props.supportedFormats}
      />
      <ImportResult
        importRun={props.importRun}
        importRunSummary={props.importRunSummary}
        onOpenDiagnostics={openDiagnostics}
      />
      <ParserErrors errors={props.importParseErrors} />
      <RecentImports
        {...props}
        diagnosticsOpen={diagnosticsOpen}
        diagnosticsRunId={diagnosticsRunId}
        onDiagnosticsOpenChange={setDiagnosticsOpen}
        onOpenDiagnostics={openDiagnostics}
      />
    </div>
  )
}
