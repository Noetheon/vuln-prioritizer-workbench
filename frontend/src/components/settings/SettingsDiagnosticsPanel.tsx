import type { ProviderStatusPublic, WorkbenchStatus } from "@/api-client"

import {
  VpwCodeBlock,
  VpwStatusBanner,
  VpwTableCard,
} from "@/components/vpw"
import { providerSnapshotSummary } from "@/lib/provider-format"
import {
  type evidenceReadiness,
  safeDiagnosticsCode,
} from "./settings-workbench-model"
import { SettingsFactRows } from "./SettingsFactRows"

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
    <VpwTableCard
      description="Support-only facts for troubleshooting. Expand JSON only when you need to share safe diagnostics."
      eyebrow="Diagnostics"
      title="Safe diagnostics"
    >
      <SettingsFactRows
        items={[
          { label: "Frontend", value: "Vite app" },
          {
            label: "Backend version",
            value: status?.core_version ?? "Not reported",
          },
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

      <details className="group rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]">
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

      <VpwStatusBanner title="Generated client stays managed" tone="warning">
        API contracts are consumed through the generated client and should not
        be edited by hand.
      </VpwStatusBanner>
    </VpwTableCard>
  )
}
