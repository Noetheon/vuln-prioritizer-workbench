import { ChevronDown, FileInput } from "lucide-react"
import type { FormEvent } from "react"
import { Button } from "../ui/button"
import { VpwField, VpwFileInput, VpwKeyValueList } from "../vpw"

export type AssetContextImportFormProps = {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  importAssetContext: (event: FormEvent<HTMLFormElement>) => void
  projectCount: number
  setAssetContextFile: (file: File | null) => void
}

export function AssetContextImportForm({
  activeProjectLabel,
  assetActionLoading,
  assetContextFile,
  importAssetContext,
  projectCount,
  setAssetContextFile,
}: AssetContextImportFormProps) {
  return (
    <div className="flex flex-col gap-4">
      <form
        aria-label="Import Asset Context form fields"
        className="flex flex-col gap-4"
        onSubmit={importAssetContext}
      >
        <VpwField
          description="Accepted CSV context can update target reference, owner, business service, environment, exposure and criticality."
          htmlFor="asset-context-csv"
          label="Asset context CSV"
        >
          <VpwFileInput
            accept=".csv,text/csv"
            file={assetContextFile}
            id="asset-context-csv"
            label="Asset context CSV"
            onFileChange={setAssetContextFile}
          />
        </VpwField>
        <Button
          aria-busy={assetActionLoading}
          disabled={
            assetActionLoading || projectCount === 0 || !assetContextFile
          }
          type="submit"
        >
          <FileInput aria-hidden="true" />
          Upload context
        </Button>
      </form>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Selected file",
            value: assetContextFile?.name ?? "None selected",
          },
          {
            label: "Target project",
            value: activeProjectLabel,
          },
        ]}
      />
      <details className="group rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="vpw-label text-[var(--vpw-teal)]">
              Supported CSV context
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              Use existing asset context fields only; scanner discovery is not
              part of this workflow.
            </span>
          </span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-180"
          />
        </summary>
        <div className="border-t border-[var(--vpw-border-subtle)] px-5 py-4 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Include target ref or asset key plus any of owner, business service,
          environment, exposure and criticality. Blank optional fields leave the
          asset context local and editable.
        </div>
      </details>
    </div>
  )
}
