import { Check, ChevronRight, Circle, X } from "lucide-react"
import type { ImportReadinessCheck } from "@/lib/import-format-metadata"

export function ReadinessOverview({
  readiness,
}: {
  readiness: readonly ImportReadinessCheck[]
}) {
  const visibleChecks = readiness.filter(
    (check) =>
      check.id !== "asset-context" &&
      check.id !== "vex" &&
      check.id !== "attack-context",
  )
  const contextChecks = readiness.filter(
    (check) =>
      (check.id === "asset-context" ||
        check.id === "vex" ||
        check.id === "attack-context") &&
      (check.status === "passed" ||
        check.status === "warning" ||
        check.status === "error"),
  )
  return (
    <div className="mt-3">
      <div className="grid gap-2 sm:grid-cols-3">
        {visibleChecks.map((check) => (
          <ReadinessCompactRow check={check} key={check.id} />
        ))}
      </div>
      {contextChecks.length > 0 ? (
        <details className="group mt-3">
          <summary className="inline-flex cursor-pointer list-none items-center gap-2 text-sm font-medium text-[var(--vpw-text-secondary)] transition-colors hover:text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
            <ChevronRight
              aria-hidden="true"
              className="size-4 transition-transform group-open:rotate-90"
            />
            Context checks
          </summary>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {contextChecks.map((check) => (
              <ReadinessCompactRow check={check} key={check.id} />
            ))}
          </div>
        </details>
      ) : null}
      <details className="group mt-3">
        <summary className="inline-flex cursor-pointer list-none items-center gap-2 text-xs font-medium text-[var(--vpw-text-muted)] transition-colors hover:text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
          <ChevronRight
            aria-hidden="true"
            className="size-4 transition-transform group-open:rotate-90"
          />
          Full validation log
        </summary>
        <ReadinessList readiness={readiness} />
      </details>
    </div>
  )
}

function ReadinessCompactRow({ check }: { check: ImportReadinessCheck }) {
  return (
    <div
      className="flex min-w-0 items-center gap-2 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2"
      title={check.message || readinessStatusLabel(check.status)}
    >
      <ReadinessIcon status={check.status} />
      <span className="min-w-0 truncate text-sm font-medium leading-5 text-[var(--vpw-text-primary)]">
        {readinessShortLabel(check)}
      </span>
      <span className="sr-only">
        {check.message || readinessStatusLabel(check.status)}
      </span>
    </div>
  )
}

function readinessShortLabel(check: ImportReadinessCheck) {
  switch (check.id) {
    case "project":
      return "Project selected"
    case "input-type":
      return "Input type selected"
    case "evidence-file":
      return "Evidence uploaded"
    case "file-type":
      return "File type checked"
    case "parser-preview":
      return "Preview ready"
    case "provider-data":
      return "Provider data ready"
    case "asset-context":
      return "Asset context checked"
    case "vex":
      return "VEX checked"
    case "attack-context":
      return "ATT&CK context checked"
    default:
      return check.label
  }
}

function readinessStatusLabel(status: ImportReadinessCheck["status"]) {
  if (status === "passed") return "Ready."
  if (status === "warning") return "Warning, import can continue."
  if (status === "missing") return "Required before import."
  if (status === "error") return "Needs attention."
  return "Pending."
}

function ReadinessList({
  readiness,
}: {
  readiness: readonly ImportReadinessCheck[]
}) {
  return (
    <div className="mt-3 overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-sm">
      {readiness.map((check) => (
        <div
          className="grid gap-2 border-b border-[var(--vpw-border-subtle)] px-3 py-2.5 last:border-b-0 sm:grid-cols-[1.25rem_minmax(8rem,0.8fr)_minmax(0,1.2fr)] sm:items-start"
          key={check.id}
        >
          <ReadinessIcon status={check.status} />
          <p className="min-w-0 font-medium text-[var(--vpw-text-primary)]">
            {check.label}
          </p>
          {check.message ? (
            <p className="min-w-0 text-xs leading-5 text-[var(--vpw-text-secondary)] [overflow-wrap:anywhere] sm:text-right">
              {check.message}
            </p>
          ) : (
            <p className="text-xs leading-5 text-[var(--vpw-text-muted)] sm:text-right">
              No additional action.
            </p>
          )}
        </div>
      ))}
    </div>
  )
}

function ReadinessIcon({ status }: { status: ImportReadinessCheck["status"] }) {
  const className =
    status === "passed"
      ? "text-[var(--vpw-green)]"
      : status === "missing" || status === "error"
        ? "text-[var(--vpw-red)]"
        : status === "warning"
          ? "text-[var(--vpw-amber)]"
          : "text-[var(--vpw-text-muted)]"
  const Icon =
    status === "passed"
      ? Check
      : status === "missing" || status === "error"
        ? X
        : Circle
  return (
    <Icon aria-hidden="true" className={`mt-0.5 size-4 shrink-0 ${className}`} />
  )
}
