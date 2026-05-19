import type { VpwDataTableColumn } from "@/components/vpw"
import { joinedValues, stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"

import type { FindingOccurrenceRow } from "./finding-detail-model"

export function buildFindingOccurrenceColumns(): readonly VpwDataTableColumn<FindingOccurrenceRow>[] {
  return [
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
}
