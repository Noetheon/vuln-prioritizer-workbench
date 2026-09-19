import { useState } from "react"
import type { AnalysisRunSummaryPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatDateTime } from "@/lib/date-format"
import { sbomAssessmentOutcome } from "./sbom-assessment-model"

export function ImportSbomAssessment({
  assessment,
  onRescan,
  rescanLoading,
  rescanError,
  onDownload,
  downloadLoading,
  downloadError,
}: {
  assessment: NonNullable<
    AnalysisRunSummaryPublic["evidence"]
  >["sbom_assessment"]
  onRescan: (updateDatabase: boolean) => void
  rescanLoading: boolean
  rescanError: string
  onDownload: () => void
  downloadLoading: boolean
  downloadError: string
}) {
  const [updateDatabase, setUpdateDatabase] = useState(true)
  if (!assessment) return null
  const outcome = sbomAssessmentOutcome(assessment)
  const warnings = [...new Set(assessment.warnings ?? [])]
  return (
    <VpwPanel className="grid gap-4">
      <VpwSectionHeader
        description={assessment.target_ref}
        title="SBOM assessment"
      />
      <VpwStatusBanner title={outcome.title} tone={outcome.tone}>
        {outcome.description}
      </VpwStatusBanner>
      <VpwKeyValueList
        columns={2}
        density="compact"
        items={[
          { label: "Inventory components", value: assessment.component_count },
          {
            label: "Identified components",
            value: assessment.identified_component_count,
          },
          {
            label: "Missing versions",
            value: assessment.version_missing_count,
          },
          { label: "Scanner matches", value: assessment.scanner_match_count },
          {
            label: "Prioritized CVE matches",
            value: assessment.prioritized_match_count,
          },
          {
            label: "Unassigned matches",
            value: assessment.unassigned_match_count,
          },
          {
            label: "Scanner",
            value: `${assessment.scanner ?? "grype"} ${assessment.scanner_version}`,
          },
          {
            label: "Database built",
            value: assessment.database_built_at
              ? formatDateTime(assessment.database_built_at)
              : "Not recorded",
          },
          { label: "Assessed", value: formatDateTime(assessment.scanned_at) },
          {
            label: "Inventory observed",
            value: assessment.observed_at
              ? formatDateTime(assessment.observed_at)
              : "Not recorded",
          },
        ]}
      />
      <p className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
        Identified components have usable identifiers; this count does not
        establish scanner coverage. Results depend on the supplied inventory and
        the recorded vulnerability database.
      </p>
      {warnings.length > 0 ? (
        <ul className="grid list-disc gap-1 pl-5 text-sm text-[var(--vpw-text-secondary)]">
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      ) : null}
      <details className="min-w-0 text-sm">
        <summary className="cursor-pointer font-medium">
          Scan provenance
        </summary>
        <dl className="mt-3 grid gap-2 [overflow-wrap:anywhere]">
          <dt className="vpw-label">Input SHA-256</dt>
          <dd className="font-mono text-xs">{assessment.input_sha256}</dd>
          <dt className="vpw-label">Scanner report SHA-256</dt>
          <dd className="font-mono text-xs">{assessment.output_sha256}</dd>
          <dt className="vpw-label">Database SHA-256</dt>
          <dd className="font-mono text-xs">
            {assessment.database_sha256 ?? "Not recorded"}
          </dd>
          {assessment.source_run_id ? (
            <>
              <dt className="vpw-label">Source run</dt>
              <dd>{assessment.source_run_id}</dd>
            </>
          ) : null}
        </dl>
      </details>
      <div className="grid gap-2">
        <Button
          className="w-fit"
          disabled={downloadLoading}
          onClick={onDownload}
          type="button"
          variant="outline"
        >
          {downloadLoading ? "Downloading evidence…" : "Download SBOM evidence"}
        </Button>
        <p className="text-xs leading-5 text-[var(--vpw-text-secondary)]">
          Includes the original SBOM and scanner evidence. Review private
          package and application details before sharing.
        </p>
        {downloadError ? (
          <VpwStatusBanner
            title="SBOM evidence could not be downloaded"
            tone="critical"
          >
            {downloadError}
          </VpwStatusBanner>
        ) : null}
      </div>
      <div className="grid gap-3 border-t border-[var(--vpw-border-subtle)] pt-4">
        <p className="text-sm text-[var(--vpw-text-secondary)]">
          Reassess the saved inventory in a new run. Its original observation
          time is preserved.
        </p>
        <label
          className="flex items-center gap-2 text-sm"
          htmlFor="sbom-rescan-update"
        >
          <Input
            checked={updateDatabase}
            className="size-4 min-w-4 p-0"
            disabled={rescanLoading}
            id="sbom-rescan-update"
            onChange={(event) => setUpdateDatabase(event.target.checked)}
            type="checkbox"
          />
          Allow database downloads for this rescan
        </label>
        <Button
          className="w-fit"
          disabled={rescanLoading}
          onClick={() => onRescan(updateDatabase)}
          type="button"
          variant="outline"
        >
          {rescanLoading ? "Queuing SBOM rescan…" : "Rescan saved SBOM"}
        </Button>
        {rescanError ? (
          <VpwStatusBanner title="SBOM rescan could not start" tone="critical">
            {rescanError}
          </VpwStatusBanner>
        ) : null}
      </div>
    </VpwPanel>
  )
}
