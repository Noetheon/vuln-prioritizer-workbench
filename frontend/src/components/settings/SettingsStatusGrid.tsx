import type { ProviderStatusPublic, WorkbenchStatus } from "@/api-client"
import { Cpu, Database, Laptop, ShieldCheck } from "lucide-react"
import {
  MetricStrip,
  type MetricStripMetric,
  type VpwCompactTone,
} from "@/components/vpw"
import { formatCacheAge } from "@/lib/provider-format"
import {
  evidenceReadiness,
  providerHealth,
} from "./settings-workbench-model"

type SettingsStatusGridProps = {
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  status: WorkbenchStatus | null
  statusError: string
}

export function SettingsStatusGrid({
  providerStatus,
  providerStatusError,
  status,
  statusError,
}: SettingsStatusGridProps) {
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )
  const backendTone: VpwCompactTone = statusError ? "critical" : "success"
  const providerTone: VpwCompactTone =
    provider.tone === "success" ? "success" : "warning"
  const evidenceTone: VpwCompactTone =
    evidence.tone === "critical"
      ? "critical"
      : evidence.tone === "success"
        ? "success"
        : "warning"
  const metrics: MetricStripMetric[] = [
    {
      description: "Single-user scope",
      icon: <Laptop aria-hidden="true" />,
      label: "Workspace Mode",
      tone: "info",
      value: "Local workspace",
    },
    {
      description: statusError
        ? "Check server logs"
        : `Core Version: ${status?.core_version || "1.1.0"}`,
      icon: <Cpu aria-hidden="true" />,
      label: "Backend API",
      tone: backendTone,
      value: (
        <span className="inline-flex min-w-0 items-center gap-2">
          <span className="truncate">
            {statusError ? "Offline" : "API Connected"}
          </span>
          <StatusPulse tone={statusError ? "red" : "green"} />
        </span>
      ),
    },
    {
      description: `Cache age: ${formatCacheAge(providerStatus?.cache_age_seconds)}`,
      icon: <Database aria-hidden="true" />,
      label: "Providers Health",
      tone: providerTone,
      value: provider.tone === "success" ? "All synced" : "Needs attention",
    },
    {
      description:
        evidence.tone === "success"
          ? "Ready for generation"
          : "Review provider and backend status",
      icon: <ShieldCheck aria-hidden="true" />,
      label: "Evidence Center",
      tone: evidenceTone,
      value: evidence.label,
    },
  ]

  return (
    <MetricStrip
      aria-label="Workspace runtime status"
      className="settings-context-strip"
      metrics={metrics}
      minCardWidth="12rem"
    />
  )
}

function StatusPulse({ tone }: { tone: "green" | "red" }) {
  const className =
    tone === "green" ? "bg-[var(--vpw-green)]" : "bg-[var(--vpw-red)]"

  return (
    <span className="relative flex h-2 w-2">
      <span
        className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${className}`}
      />
      <span className={`relative inline-flex h-2 w-2 rounded-full ${className}`} />
    </span>
  )
}
