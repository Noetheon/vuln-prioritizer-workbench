import type { ReportPublic } from "@/api-client"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { StatusLozenge } from "@/components/vpw"
import { reportFormatLabel } from "@/lib/report-format"

export function ReportArtifactCell({ report }: { report: ReportPublic }) {
  return (
    <div className="min-w-0">
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate font-mono text-xs font-medium">
          {report.filename}
        </span>
      </div>
      <p className="mt-1 text-xs text-[var(--vpw-text-secondary)]">
        {reportFormatLabel(report.format)}
      </p>
    </div>
  )
}

export function ReportStatusCell({
  report,
  verificationFailed,
  verificationInProgress,
  verificationOk,
}: {
  report: ReportPublic
  verificationFailed: boolean
  verificationInProgress: boolean
  verificationOk: boolean
}) {
  const status = verificationInProgress
    ? "in_review"
    : verificationOk
      ? "succeeded"
      : verificationFailed
        ? "failed"
        : "succeeded"
  const label = verificationInProgress
    ? "Verifying"
    : verificationOk
      ? "Verified"
      : verificationFailed
        ? "Verify failed"
        : report.format === "zip"
          ? "Bundle available"
          : "Generated"

  return <StatusLozenge density="compact" label={label} status={status} />
}

export function ReportVerificationCell({ label }: { label: string }) {
  const status =
    label === "Verified" || label === "Checksum recorded"
      ? "succeeded"
      : label === "Verification failed"
        ? "failed"
        : label === "Verification running" || label === "Verification pending"
          ? "review_due"
          : "unknown"
  return <StatusLozenge density="compact" label={label} status={status} />
}

export function ReportChecksumCell({ report }: { report: ReportPublic }) {
  const checksum = `${report.sha256.slice(0, 12)}...`

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-default font-mono text-xs text-[var(--vpw-text-secondary)]">
            {checksum}
          </span>
        </TooltipTrigger>
        <TooltipContent>{report.sha256}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
