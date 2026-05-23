import { useState } from "react"
import { VpwPageStack, VpwStatusBanner } from "@/components/vpw"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import {
  ImportDiagnosticsDrawer,
  ImportRunDetailRoute,
  ImportsHomeRoute,
  NewImportRoute,
  SupportedFormatsRoute,
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

  const diagnosticsDrawer = (
    <ImportDiagnosticsDrawer
      diagnosticsOpen={diagnosticsOpen}
      diagnosticsRunId={diagnosticsRunId}
      onDiagnosticsOpenChange={setDiagnosticsOpen}
      runDetailError={props.runDetailError}
      runDetailLoading={props.runDetailLoading}
      selectedRun={props.selectedRun}
      selectedRunId={props.selectedRunId}
      selectedRunSummary={props.selectedRunSummary}
    />
  )

  return (
    <VpwPageStack>
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
      {props.view === "new" ? (
        <NewImportRoute {...props} onOpenDiagnostics={openDiagnostics} />
      ) : null}
      {props.view === "run" ? (
        <ImportRunDetailRoute {...props} onOpenDiagnostics={openDiagnostics} />
      ) : null}
      {props.view === "formats" ? <SupportedFormatsRoute {...props} /> : null}
      {!props.view || props.view === "home" ? (
        <ImportsHomeRoute
          {...props}
          diagnosticsOpen={diagnosticsOpen}
          diagnosticsRunId={diagnosticsRunId}
          onDiagnosticsOpenChange={setDiagnosticsOpen}
          onOpenDiagnostics={openDiagnostics}
        />
      ) : null}
      {diagnosticsDrawer}
    </VpwPageStack>
  )
}
