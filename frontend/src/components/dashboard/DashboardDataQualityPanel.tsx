import { AlertCircle, CheckCircle2 } from "lucide-react"
import {
  VpwBadge,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"

type DashboardDataQualityPanelProps = {
  dataQualityError: string | null
  dataQualityWarnings: readonly string[]
}

export function DashboardDataQualityPanel({
  dataQualityError,
  dataQualityWarnings,
}: DashboardDataQualityPanelProps) {
  const qualityIssueCount =
    dataQualityWarnings.length + (dataQualityError ? 1 : 0)

  return (
    <VpwSurface className="gap-3 py-4">
      <VpwSurfaceHeader className="px-4 pb-0">
        <div className="flex items-center justify-between gap-3">
          <VpwSurfaceTitle className="text-sm">Data Quality</VpwSurfaceTitle>
          <VpwBadge tone={qualityIssueCount > 0 ? "warning" : "success"}>
            {qualityIssueCount > 0 ? `${qualityIssueCount} issue(s)` : "Clear"}
          </VpwBadge>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="px-4">
        {dataQualityWarnings.length === 0 && !dataQualityError ? (
          <ul className="flex flex-col gap-3">
            {[
              "No data quality issues detected.",
              "All providers reporting normally.",
              "Evidence context available for bundle generation.",
            ].map((item) => (
              <li
                className="flex items-center gap-2 text-xs text-muted-foreground"
                key={item}
              >
                <CheckCircle2 className="size-3.5 shrink-0 text-[var(--vpw-green)]" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        ) : (
          <ul className="flex flex-col gap-2">
            {dataQualityWarnings.map((warning) => (
              <li className="flex gap-2 text-xs" key={warning}>
                <AlertCircle
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-[var(--vpw-amber)]"
                />
                <span className="leading-relaxed text-muted-foreground">
                  {warning}
                </span>
              </li>
            ))}
            {dataQualityError && (
              <li className="flex gap-2 text-xs">
                <AlertCircle
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-[var(--vpw-red)]"
                />
                <span className="leading-relaxed text-muted-foreground">
                  {dataQualityError}
                </span>
              </li>
            )}
          </ul>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
