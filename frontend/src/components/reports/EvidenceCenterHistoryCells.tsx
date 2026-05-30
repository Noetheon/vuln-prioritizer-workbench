import type { ReportPublic } from "@/api-client"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { StatusLozenge } from "@/components/vpw"
import { reportFormatLabel } from "@/lib/report-format"
import { workflowStageLabel, workflowStatusLabel } from "@/workbench/workflow-model"

export function ReportArtifactCell({ report }: { report: ReportPublic }) {
  return (
    <div className="min-w-0">
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate font-mono text-xs font-medium">
          {report.filename}
        </span>
      </div>
      <p className="mt-1 text-xs text-[var(--vpw-text-secondary)]">
        {reportFormatLabel(report.format)} · {workflowStageLabel(report.workflow)}
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
  let status = "succeeded"
  let label =
    report.format === "zip" ? "Bundle available" : "Generated"

  if (verificationInProgress) {
    status = "in_review"
    label = "Verifying"
  } else if (report.workflow?.status === "failed") {
    status = "failed"
    label = "Generation failed"
  } else if (
    report.workflow?.status === "running" ||
    report.workflow?.status === "pending"
  ) {
    status = "in_review"
    label = workflowStatusLabel(report.workflow)
  } else if (verificationOk) {
    label = "Verified"
  } else if (verificationFailed) {
    status = "failed"
    label = "Verify failed"
  }

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
