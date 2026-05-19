import { Check } from "lucide-react"
import { Button } from "@/components/ui/button"
import { VpwPanel } from "@/components/vpw"
import type { ImportReadinessCheck } from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"
import {
  blockedStepReason,
  checkHasStatus,
  checkPassed,
  type StepId,
  stepLabels,
} from "./new-import-route-state"

export function StepNav({
  currentStep,
  onStepChange,
  readiness,
}: {
  currentStep: StepId
  onStepChange: (step: StepId) => void
  readiness: readonly ImportReadinessCheck[]
}) {
  const canReachStep2 =
    checkPassed(readiness, "project") && checkPassed(readiness, "input-type")
  const parserReady =
    checkPassed(readiness, "parser-preview") ||
    checkHasStatus(readiness, "parser-preview", "warning")
  const canReachStep3 =
    canReachStep2 &&
    checkPassed(readiness, "evidence-file") &&
    checkPassed(readiness, "file-type") &&
    parserReady
  const canReachStep4 = canReachStep3

  return (
    <VpwPanel className="overflow-hidden p-0 lg:h-full">
      <ol className="relative flex flex-col gap-1.5 p-3">
        {stepLabels.map((item, index) => {
          const reachable =
            item.id === 1 ||
            (item.id === 2 && canReachStep2) ||
            (item.id === 3 && canReachStep3) ||
            (item.id === 4 && canReachStep4)
          const completed = item.id < currentStep
          const active = item.id === currentStep
          const blockedReason = reachable
            ? ""
            : blockedStepReason(item.id, canReachStep2, canReachStep3)
          const accessibleDescription = blockedReason || item.description
          const visualDescription =
            blockedReason === "Select project and input type first."
              ? "Choose source first."
              : blockedReason === "Upload a valid evidence file first."
                ? "Upload evidence first."
                : accessibleDescription
          return (
            <li className="relative" key={item.id}>
              {index < stepLabels.length - 1 ? (
                <span
                  aria-hidden="true"
                  className={cn(
                    "absolute top-8 bottom-[-0.85rem] left-[1.55rem] w-px",
                    completed
                      ? "bg-[var(--vpw-green)]"
                      : "bg-[var(--vpw-border-default)]",
                  )}
                />
              ) : null}
              <Button
                aria-current={active ? "step" : undefined}
                className={cn(
                  "relative z-10 grid h-auto min-h-[3.875rem] w-full grid-cols-[2.25rem_minmax(0,1fr)] items-center justify-start gap-2.5 rounded-[var(--vpw-radius-md)] px-2.5 py-2.5 text-left whitespace-normal transition-[background,box-shadow,color]",
                  active
                    ? "bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)] ring-1 ring-[var(--vpw-border-default)]"
                    : "bg-transparent",
                  reachable
                    ? "hover:bg-[var(--vpw-bg-panel)]"
                    : "cursor-not-allowed opacity-80",
                )}
                disabled={!reachable}
                onClick={() => reachable && onStepChange(item.id)}
                size="default"
                title={blockedReason || undefined}
                type="button"
                variant="ghost"
              >
                <span
                  className={cn(
                    "relative z-10 flex size-7 shrink-0 items-center justify-center rounded-full border bg-[var(--vpw-bg-card)] font-mono text-[0.72rem] font-semibold",
                    completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-green)] text-[var(--vpw-bg-card)]",
                    active &&
                      !completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-green)] text-[var(--vpw-bg-card)]",
                    !active &&
                      !completed &&
                      "border-[var(--vpw-border-strong)] text-[var(--vpw-text-muted)]",
                  )}
                >
                  {completed ? (
                    <Check aria-hidden="true" className="size-3.5" />
                  ) : (
                    item.id
                  )}
                </span>
                <span className="min-w-0">
                  <span
                    className={cn(
                      "block text-[0.8125rem] font-semibold leading-4",
                      active
                        ? "text-[var(--vpw-text-primary)]"
                        : "text-[var(--vpw-text-secondary)]",
                    )}
                  >
                    {item.label}
                  </span>
                  <span className="mt-1 block text-[0.72rem] leading-4 text-[var(--vpw-text-muted)]">
                    {visualDescription}
                  </span>
                </span>
              </Button>
            </li>
          )
        })}
      </ol>
    </VpwPanel>
  )
}
