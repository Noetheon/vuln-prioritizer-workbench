import type { ReportPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import type { ArtifactCard } from "@/lib/report-capability-catalog"
import type { ReportFormat } from "@/lib/report-format"
import { generatedActionLabel } from "./evidence-center-model"

export function ArtifactActions({
  card,
  className,
  disabledByContext = false,
  format,
  generateVariant = "default",
  generating,
  onCreateReport,
  onDownloadReport,
  onVerifyReport,
  report,
  reportActionsEnabled,
}: {
  card: ArtifactCard | null
  className?: string
  disabledByContext?: boolean
  format: ReportFormat
  generateVariant?: "default" | "outline"
  generating: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onVerifyReport?: (report: ReportPublic) => Promise<void>
  report: ReportPublic | null
  reportActionsEnabled: boolean
}) {
  return (
    <div className={`flex flex-wrap gap-2 ${className ?? ""}`}>
      <Button
        aria-busy={generating}
        disabled={!reportActionsEnabled || generating || disabledByContext}
        onClick={() => void onCreateReport(format)}
        size="sm"
        type="button"
        variant={generateVariant}
      >
        {generating ? "Generating" : generatedActionLabel(card, report)}
      </Button>
      {report ? (
        <Button
          onClick={() => void onDownloadReport(report)}
          size="sm"
          type="button"
          variant="outline"
        >
          Download
        </Button>
      ) : null}
      {onVerifyReport && report?.format === "zip" ? (
        <Button
          onClick={() => void onVerifyReport(report)}
          size="sm"
          type="button"
          variant="outline"
        >
          Verify bundle
        </Button>
      ) : null}
    </div>
  )
}
