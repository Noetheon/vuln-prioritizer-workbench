import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { joinedValues, stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"

import type {
  FindingDetailRow,
  FindingOccurrenceRow,
} from "./finding-detail-model"

export type FindingEvidenceTabProps = {
  dataQualityRows: readonly {
    code: string
    key: string
    message: string
    severity: string
    source: string
  }[]
  evidenceRows: readonly FindingDetailRow[]
  occurrences: readonly FindingOccurrenceRow[]
}

const occurrenceColumns: readonly VpwDataTableColumn<FindingOccurrenceRow>[] = [
  {
    cell: (occurrence) => (
      <>
        <span className="font-medium">
          {optionalText(
            stringValue(occurrence.source_format) ??
              stringValue(occurrence.source),
          )}
        </span>
        <small className="vpw-table-subtext">
          {optionalText(
            stringValue(occurrence.source_record_id) ??
              stringValue(occurrence.raw_reference),
          )}
        </small>
      </>
    ),
    header: "Source",
    id: "source",
  },
  {
    cell: (occurrence) => (
      <>
        <span className="font-medium">
          {joinedValues([
            stringValue(occurrence.component_name),
            stringValue(occurrence.component_version),
          ])}
        </span>
        <small className="vpw-table-subtext">
          {optionalText(stringValue(occurrence.purl))}
        </small>
      </>
    ),
    header: "Component",
    id: "component",
  },
  {
    cell: (occurrence) => (
      <>
        <span className="font-medium">
          {optionalText(
            stringValue(occurrence.asset_ref) ??
              stringValue(occurrence.target_ref),
          )}
        </span>
        <small className="vpw-table-subtext">
          {joinedValues([
            stringValue(occurrence.asset_owner),
            stringValue(occurrence.asset_business_service),
            labelize(stringValue(occurrence.asset_exposure)),
          ])}
        </small>
      </>
    ),
    header: "Asset / Owner",
    id: "asset",
  },
  {
    cell: (occurrence) => (
      <>
        <span className="font-medium">
          {optionalText(stringValue(occurrence.scanner))}
        </span>
        <small className="vpw-table-subtext">
          {optionalText(stringValue(occurrence.raw_severity))}
        </small>
      </>
    ),
    header: "Evidence",
    id: "evidence",
  },
  {
    cell: (occurrence) => {
      const fixVersions =
        Array.isArray(occurrence.fix_versions) &&
        occurrence.fix_versions.length > 0
          ? occurrence.fix_versions.join(", ")
          : stringValue(occurrence.fix_version)

      return (
        <>
          <span className="font-medium">{optionalText(fixVersions)}</span>
          <small className="vpw-table-subtext">
            {optionalText(
              stringValue(occurrence.vex_status)
                ? labelize(stringValue(occurrence.vex_status))
                : stringValue(occurrence.vex_justification),
            )}
          </small>
        </>
      )
    },
    header: "Fix / VEX",
    id: "fix",
  },
]

export function FindingEvidenceTab({
  dataQualityRows,
  evidenceRows,
  occurrences,
}: FindingEvidenceTabProps) {
  return (
    <section
      className="finding-evidence-tab-layout"
      aria-label="Evidence workspace"
    >
      <section className="finding-evidence-grid" aria-label="Evidence summary">
        {evidenceRows.map((row, index) => (
          <VpwSurface
            className={cn(
              "finding-evidence-summary-card",
              index === 0 ? "finding-evidence-summary-card-primary" : undefined,
              index > 0 ? "finding-evidence-summary-card-secondary" : undefined,
            )}
            key={row.label}
          >
            <VpwSurfaceHeader>
              <VpwSurfaceDescription className="finding-evidence-summary-description">
                {row.label}
              </VpwSurfaceDescription>
              <VpwSurfaceTitle className="finding-evidence-summary-title">
                {row.value}
              </VpwSurfaceTitle>
            </VpwSurfaceHeader>
            <VpwSurfaceBody>
              <p>{row.detail}</p>
            </VpwSurfaceBody>
          </VpwSurface>
        ))}
      </section>

      <section
        className="finding-evidence-detail-grid"
        aria-label="Evidence detail"
      >
        <VpwSurface
          aria-label="Scanner occurrences"
          className="finding-tab-card finding-occurrences-card"
        >
          <VpwSurfaceHeader>
            <div className="finding-card-heading">
              <div>
                <VpwSurfaceDescription>Scanner evidence</VpwSurfaceDescription>
                <VpwSurfaceTitle>Occurrences</VpwSurfaceTitle>
              </div>
              <VpwBadge tone="info">
                {occurrences.length} source row(s)
              </VpwBadge>
            </div>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            {occurrences.length > 0 ? (
              <VpwDataTable
                caption="Occurrences table"
                className="finding-detail-table-wrap"
                columns={occurrenceColumns}
                data={occurrences}
                getRowKey={(occurrence, index) =>
                  stringValue(occurrence.id) ?? `occurrence-${index + 1}`
                }
                minWidth="960px"
                variant="detail"
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                No source occurrences have been recorded for this finding.
              </p>
            )}
          </VpwSurfaceBody>
        </VpwSurface>

        <VpwSurface
          aria-label="Data quality notes"
          className="finding-tab-card finding-data-quality-card"
        >
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Provider data</VpwSurfaceDescription>
            <VpwSurfaceTitle>Data quality notes</VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            {dataQualityRows.length > 0 ? (
              <ul className="finding-data-quality-list">
                {dataQualityRows.map((flag) => (
                  <li key={flag.key}>
                    <strong>{labelize(flag.code)}</strong>
                    <span>
                      {flag.source} / {labelize(flag.severity)}
                    </span>
                    <p>{flag.message}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">
                No data quality flags recorded.
              </p>
            )}
          </VpwSurfaceBody>
        </VpwSurface>
      </section>
    </section>
  )
}
