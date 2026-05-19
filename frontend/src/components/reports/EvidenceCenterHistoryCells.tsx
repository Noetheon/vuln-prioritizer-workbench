import type { ReportPublic } from "@/api-client"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { StatusLozenge, VpwBadge } from "@/components/vpw"
import { reportFormatLabel } from "@/lib/report-format"

export function ReportArtifactCell({
  isDemo,
  report,
}: {
  isDemo: boolean
  report: ReportPublic
}) {
  return (
    <div className="min-w-0">
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate font-mono text-xs font-medium">
          {report.filename}
        </span>
        {isDemo ? <VpwBadge tone="warning">Demo</VpwBadge> : null}
      </div>
      <p className="mt-1 text-xs text-[var(--vpw-text-secondary)]">
        {reportFormatLabel(report.format)}
      </p>
    </div>
  )
}

export function ReportStatusCell({
  isDemo,
  report,
  verificationFailed,
  verificationInProgress,
  verificationOk,
}: {
  isDemo: boolean
  report: ReportPublic
  verificationFailed: boolean
  verificationInProgress: boolean
  verificationOk: boolean
}) {
  const status = isDemo
    ? "ready"
    : verificationInProgress
      ? "in_review"
      : verificationOk
        ? "succeeded"
        : verificationFailed
          ? "failed"
          : "succeeded"
  const label = isDemo
    ? "Demo"
    : verificationInProgress
      ? "Verifying"
      : verificationOk
        ? "Verified"
        : verificationFailed
          ? "Verify failed"
          : report.format === "zip"
            ? "Bundle"
            : "Generated"

  return <StatusLozenge density="compact" label={label} status={status} />
}

export function ReportChecksumCell({ report }: { report: ReportPublic }) {
  const realChecksum = !report.sha256.startsWith("demo-only")
  const checksum = realChecksum
    ? `${report.sha256.slice(0, 12)}...`
    : "Demo preview"

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-default font-mono text-xs text-[var(--vpw-text-secondary)]">
            {checksum}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {realChecksum ? report.sha256 : "Demo preview - not a real checksum"}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
