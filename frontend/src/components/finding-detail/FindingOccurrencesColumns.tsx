import type { VpwDataTableColumn } from "@/components/vpw"
import { stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"

import type { FindingOccurrenceRow } from "./finding-detail-model"

export function buildFindingOccurrenceColumns(): readonly VpwDataTableColumn<FindingOccurrenceRow>[] {
  return [
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.component_name))}
        </span>
      ),
      header: "Component",
      id: "component",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.component_version))}
        </span>
      ),
      header: "Version",
      id: "version",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.purl))}
        </span>
      ),
      header: "Package / PURL",
      id: "purl",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.target_ref))}
        </span>
      ),
      header: "Asset",
      id: "asset",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.asset_business_service))}
        </span>
      ),
      header: "Service",
      id: "service",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(stringValue(occurrence.asset_owner))}
        </span>
      ),
      header: "Owner",
      id: "owner",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(labelize(stringValue(occurrence.asset_environment)))}
        </span>
      ),
      header: "Environment",
      id: "environment",
    },
    {
      cell: (occurrence) => (
        <span className="font-medium">
          {optionalText(labelize(stringValue(occurrence.asset_exposure)))}
        </span>
      ),
      header: "Exposure",
      id: "exposure",
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
    {
      cell: (occurrence) => (
        <>
          <span className="font-medium">
            {optionalText(
              stringValue(occurrence.source_format) ??
                stringValue(occurrence.source) ??
                stringValue(occurrence.scanner),
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
  ]
}
