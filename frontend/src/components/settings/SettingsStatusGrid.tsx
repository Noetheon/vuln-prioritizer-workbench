import type { ProviderStatusPublic, WorkbenchStatus } from "@/api-client"
import { Cpu, Database, Laptop, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"
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

  return (
    <div className="mt-2 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
      <StatusCard
        detail="Single-user operator scope"
        icon={<Laptop className="size-5" />}
        label="Workspace Mode"
        title="Local workspace"
        tone="blue"
      />
      <StatusCard
        detail={
          statusError
            ? "Check server logs"
            : `Core Version: ${status?.core_version || "1.1.0"}`
        }
        icon={<Cpu className="size-5" />}
        label="Backend API"
        pulseTone={statusError ? "red" : "green"}
        title={statusError ? "Offline" : "API Connected"}
        tone={statusError ? "red" : "blue"}
      />
      <StatusCard
        detail={`Cache age: ${formatCacheAge(providerStatus?.cache_age_seconds)}`}
        icon={<Database className="size-5" />}
        label="Providers Health"
        title={provider.tone === "success" ? "All synced" : "Needs attention"}
        tone={provider.tone === "success" ? "green" : "amber"}
      />
      <StatusCard
        detail={
          evidence.tone === "success"
            ? "Ready for generation"
            : "Review provider and backend status"
        }
        icon={<ShieldCheck className="size-5" />}
        label="Evidence Center"
        title={evidence.label}
        tone={evidence.tone === "success" ? "green" : "amber"}
      />
    </div>
  )
}

function StatusCard({
  detail,
  icon,
  label,
  pulseTone,
  title,
  tone,
}: {
  detail: string
  icon: ReactNode
  label: string
  pulseTone?: "green" | "red"
  title: string
  tone: "amber" | "blue" | "green" | "red"
}) {
  return (
    <div className="settings-card-glow flex items-start gap-3.5 rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4">
      <div className={`rounded-lg p-2 ${toneClass[tone]}`}>{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between">
          <span className="block font-semibold text-xs text-[var(--vpw-text-muted)] uppercase">
            {label}
          </span>
          {pulseTone ? <StatusPulse tone={pulseTone} /> : null}
        </div>
        <span className="mt-0.5 block font-bold text-sm text-[var(--vpw-text-primary)]">
          {title}
        </span>
        <span className="mt-1 block truncate text-xs text-[var(--vpw-text-secondary)]">
          {detail}
        </span>
      </div>
    </div>
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

const toneClass = {
  amber: "bg-[color-mix(in_srgb,var(--vpw-amber)_10%,transparent)] text-[var(--vpw-amber)]",
  blue: "bg-[color-mix(in_srgb,var(--vpw-blue)_10%,transparent)] text-[var(--vpw-blue)]",
  green: "bg-[color-mix(in_srgb,var(--vpw-green)_10%,transparent)] text-[var(--vpw-green)]",
  red: "bg-[color-mix(in_srgb,var(--vpw-red)_10%,transparent)] text-[var(--vpw-red)]",
} as const
