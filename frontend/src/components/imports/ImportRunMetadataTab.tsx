import {
  VpwPanel,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  jsonPreview,
  objectRecord,
} from "./imports-workbench-model"
import {
  CopyableValue,
  CopyButton,
} from "./ImportDiagnosticsDrawerParts"
import {
  RunDetailRows,
  stringFromRecord,
  type ImportRun,
  type ImportRunSummary,
} from "./ImportRunDetailTabShared"

export function MetadataTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const inputUpload = objectRecord(summary.input_upload)
  const rawJson = jsonPreview({ run, summary })
  const sha256 = stringFromRecord(inputUpload, "sha256")
  const storageRef = stringFromRecord(inputUpload, "storage_ref")
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwSectionHeader title="Run metadata" />
      <RunDetailRows
        items={[
          { label: "Run ID", value: <CopyableValue label="Copy run ID" value={summary.id} /> },
          { label: "Input type", value: summary.input_type },
          {
            label: "Provider snapshot ID",
            value: summary.provider_snapshot_id ? (
              <CopyableValue
                label="Copy provider snapshot ID"
                value={summary.provider_snapshot_id}
              />
            ) : (
              "Not recorded"
            ),
          },
          {
            label: "SHA256",
            value: sha256 ? <CopyableValue label="Copy SHA256" value={sha256} /> : "Not recorded",
          },
          {
            label: "Storage reference",
            value: storageRef ? (
              <CopyableValue label="Copy storage reference" value={storageRef} />
            ) : (
              "Not recorded"
            ),
          },
        ]}
      />
      <details>
        <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
          Raw metadata
        </summary>
        <div className="mt-3 flex justify-end">
          <CopyButton label="Copy metadata JSON" value={rawJson} />
        </div>
        <pre className="mt-3 max-h-[30rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs">
          <code>{rawJson}</code>
        </pre>
      </details>
    </VpwPanel>
  )
}
