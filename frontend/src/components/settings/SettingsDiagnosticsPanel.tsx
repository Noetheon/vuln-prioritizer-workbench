import type { ProviderStatusPublic, WorkbenchStatus } from "@/api-client"
import { ShieldAlert } from "lucide-react"
import type { ReactNode } from "react"

import {
  VpwBadge,
  type VpwBadgeTone,
  VpwCodeBlock,
  VpwPanel,
  VpwSectionHeader,
} from "@/components/vpw"
import { providerSnapshotSummary } from "@/lib/provider-format"
import {
  type evidenceReadiness,
  safeDiagnosticsCode,
} from "./settings-workbench-model"

type SettingsDiagnosticsPanelProps = {
  evidence: ReturnType<typeof evidenceReadiness>
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}

export function SettingsDiagnosticsPanel({
  evidence,
  providerStatus,
  status,
  statusError,
}: SettingsDiagnosticsPanelProps) {
  const diagnosticsCode = safeDiagnosticsCode({
    providerStatus,
    status,
    statusError,
  })

  return (
    <VpwPanel className="overflow-hidden p-0">
      <div className="border-b border-[var(--vpw-border-subtle)] bg-[color-mix(in_srgb,var(--vpw-bg-panel)_52%,var(--vpw-bg-card))] px-5 py-4">
        <VpwSectionHeader
          description="Support-only facts for troubleshooting. Expand JSON only when you need to share safe diagnostics."
          title="Diagnostics"
        />
      </div>
      <SettingsDiagnosticRows
        items={[
          { label: "Frontend", value: "Vite app" },
          { label: "Backend version", value: status?.core_version ?? "Not reported" },
          {
            label: "Provider freshness",
            value: providerSnapshotSummary(providerStatus),
          },
          {
            label: "Evidence readiness",
            value: evidence.label,
            tone: evidence.tone,
          },
        ]}
      />
      <details className="group border-t border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium text-[var(--vpw-text-primary)] marker:hidden">
          Safe diagnostics payload
          <span className="font-mono text-xs text-[var(--vpw-text-muted)] group-open:hidden">
            Expand
          </span>
          <span className="hidden font-mono text-xs text-[var(--vpw-text-muted)] group-open:inline">
            Collapse
          </span>
        </summary>
        <div className="border-t border-[var(--vpw-border-subtle)] p-3">
          <VpwCodeBlock
            code={diagnosticsCode}
            label="Safe diagnostics"
            onCopy={() => void navigator.clipboard?.writeText(diagnosticsCode)}
          />
        </div>
      </details>
      <div className="border-t border-[var(--vpw-border-subtle)] bg-[color-mix(in_srgb,var(--vpw-amber)_9%,var(--vpw-bg-card))] px-5 py-3">
        <p className="flex gap-2 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          <ShieldAlert
            aria-hidden="true"
            className="mt-1 h-4 w-4 shrink-0 text-[var(--vpw-amber)]"
          />
          <span>
            <span className="font-medium text-[var(--vpw-text-primary)]">
              Generated client stays managed.
            </span>{" "}
            API contracts are consumed through the generated client and should
            not be edited by hand.
          </span>
        </p>
      </div>
    </VpwPanel>
  )
}

type SettingsDiagnosticRow = {
  label: string
  value: ReactNode
  tone?: VpwBadgeTone
}

function SettingsDiagnosticRows({
  items,
}: {
  items: readonly SettingsDiagnosticRow[]
}) {
  return (
    <dl className="grid divide-y divide-[var(--vpw-border-subtle)] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
      {items.map((item) => (
        <div
          className="min-w-0 px-5 py-4 odd:lg:border-b odd:lg:border-[var(--vpw-border-subtle)] even:lg:border-b even:lg:border-[var(--vpw-border-subtle)]"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd className="mt-2 min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
            {item.tone ? (
              <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
            ) : (
              item.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}
