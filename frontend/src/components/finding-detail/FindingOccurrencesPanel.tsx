import {
  VpwBadge,
  VpwDataTable,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { joinedValues, stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingOccurrenceRow } from "./finding-detail-model"
import { buildFindingOccurrenceColumns } from "./FindingOccurrencesColumns"

type FindingOccurrencesPanelProps = {
  occurrences: readonly FindingOccurrenceRow[]
}

export function FindingOccurrencesPanel({
  occurrences,
}: FindingOccurrencesPanelProps) {
  return (
    <VpwSurface
      aria-label="Scanner occurrences"
      className="finding-tab-card finding-occurrences-card"
    >
      <VpwSurfaceHeader>
        <div className="finding-card-heading">
          <div>
            <VpwSurfaceDescription>Occurrence evidence</VpwSurfaceDescription>
            <VpwSurfaceTitle>Occurrences</VpwSurfaceTitle>
          </div>
          <VpwBadge tone="info">{occurrences.length} source row(s)</VpwBadge>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        {occurrences.length > 0 ? (
          <>
            <FindingOccurrencesMobileList occurrences={occurrences} />
            <VpwDataTable
              caption="Occurrences table"
              className="finding-detail-table-wrap finding-occurrences-table"
              columns={buildFindingOccurrenceColumns()}
              data={occurrences}
              getRowKey={(occurrence, index) =>
                stringValue(occurrence.id) ?? `occurrence-${index + 1}`
              }
              minWidth="1120px"
              variant="detail"
            />
          </>
        ) : (
          <p className="text-sm text-muted-foreground">
            No source occurrences have been recorded for this finding.
          </p>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}

function FindingOccurrencesMobileList({
  occurrences,
}: {
  occurrences: readonly FindingOccurrenceRow[]
}) {
  return (
    <ul
      aria-label="Occurrences mobile summary"
      className="finding-occurrences-mobile-list"
    >
      {occurrences.map((occurrence, index) => {
        const fixVersions =
          Array.isArray(occurrence.fix_versions) &&
          occurrence.fix_versions.length > 0
            ? occurrence.fix_versions.join(", ")
            : stringValue(occurrence.fix_version)
        const key =
          stringValue(occurrence.id) ?? `occurrence-mobile-${index + 1}`

        return (
          <li className="finding-occurrence-mobile-card" key={key}>
            <div>
              <span>Source</span>
              <strong>
                {optionalText(
                  stringValue(occurrence.source_format) ??
                    stringValue(occurrence.source),
                )}
              </strong>
              <small>
                {optionalText(
                  stringValue(occurrence.source_record_id) ??
                    stringValue(occurrence.raw_reference),
                )}
              </small>
            </div>
            <div>
              <span>Component</span>
              <strong>
                {joinedValues([
                  stringValue(occurrence.component_name),
                  stringValue(occurrence.component_version),
                ])}
              </strong>
              <small>{optionalText(stringValue(occurrence.purl))}</small>
            </div>
            <div>
              <span>Asset / owner</span>
              <strong>
                {optionalText(stringValue(occurrence.target_ref))}
              </strong>
              <small>
                {joinedValues([
                  stringValue(occurrence.asset_owner),
                  stringValue(occurrence.asset_business_service),
                  labelize(stringValue(occurrence.asset_exposure)),
                ])}
              </small>
            </div>
            <div>
              <span>Evidence</span>
              <strong>{optionalText(stringValue(occurrence.scanner))}</strong>
              <small>{optionalText(stringValue(occurrence.raw_severity))}</small>
            </div>
            <div>
              <span>Fix / VEX</span>
              <strong>{optionalText(fixVersions)}</strong>
              <small>
                {optionalText(
                  stringValue(occurrence.vex_status)
                    ? labelize(stringValue(occurrence.vex_status))
                    : stringValue(occurrence.vex_justification),
                )}
              </small>
            </div>
          </li>
        )
      })}
    </ul>
  )
}
