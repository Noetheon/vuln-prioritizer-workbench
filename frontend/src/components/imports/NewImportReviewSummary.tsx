import { CheckCircle2, X } from "lucide-react"
import { cn } from "@/lib/utils"
import { ReviewMetric } from "./NewImportReviewShared"

export function ReviewPreflightSummary({
  blockingCount,
  optionalContext,
  providerMessage,
  requiredPassed,
  requiredTotal,
}: {
  blockingCount: number
  optionalContext: string
  providerMessage: string
  requiredPassed: number
  requiredTotal: number
}) {
  const ready = blockingCount === 0
  return (
    <div
      className={cn(
        "rounded-[var(--vpw-radius-lg)] border p-3",
        ready
          ? "border-[color-mix(in_srgb,var(--vpw-green)_24%,var(--vpw-border-default))] bg-[color-mix(in_srgb,var(--vpw-bg-success)_54%,var(--vpw-bg-card))]"
          : "border-[color-mix(in_srgb,var(--vpw-red)_34%,var(--vpw-border-default))] bg-[color-mix(in_srgb,var(--vpw-bg-critical)_50%,var(--vpw-bg-card))]",
      )}
    >
      <div className="grid gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <span
            className={cn(
              "grid size-8 shrink-0 place-items-center rounded-full border",
              ready
                ? "border-[color-mix(in_srgb,var(--vpw-green)_28%,transparent)] bg-[var(--vpw-bg-card)] text-[var(--vpw-green)]"
                : "border-[color-mix(in_srgb,var(--vpw-red)_28%,transparent)] bg-[var(--vpw-bg-card)] text-[var(--vpw-red)]",
            )}
          >
            {ready ? (
              <CheckCircle2 aria-hidden="true" className="size-5" />
            ) : (
              <X aria-hidden="true" className="size-5" />
            )}
          </span>
          <div className="min-w-0">
            <p className="font-semibold text-[var(--vpw-text-primary)]">
              {ready ? "Ready to import" : "Review required"}
            </p>
            <p className="mt-1 max-w-[34rem] text-sm leading-5 text-[var(--vpw-text-secondary)]">
              {ready
                ? "Required checks passed. Starting the import creates a recorded run."
                : `${blockingCount} check${blockingCount === 1 ? "" : "s"} need attention before import.`}
            </p>
          </div>
        </div>
        <dl className="grid min-w-0 gap-2 text-sm sm:grid-cols-3">
          <ReviewMetric
            label="Required"
            tone={ready ? "success" : "critical"}
            value={
              ready
                ? `${requiredPassed}/${requiredTotal} passed`
                : `${blockingCount} blocked`
            }
          />
          <ReviewMetric label="Context" value={optionalContext} />
          <ReviewMetric label="Provider" value={providerMessage} />
        </dl>
      </div>
    </div>
  )
}

export function ReviewPackageSummary({
  evidenceFile,
  inputType,
  projectName,
}: {
  evidenceFile: string
  inputType: string
  projectName: string
}) {
  return (
    <dl className="grid rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] text-sm md:grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)_minmax(0,1.35fr)] md:divide-x md:divide-[var(--vpw-border-subtle)]">
      <ReviewMetric label="Project" value={projectName} />
      <ReviewMetric label="Input type" value={inputType} />
      <ReviewMetric label="Evidence file" value={evidenceFile} />
    </dl>
  )
}
