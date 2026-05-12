import { Link } from "@/lib/router"

import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwSection,
} from "@/components/vpw"
import {
  evidenceReadiness,
  providerHealth,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

type SettingsHeroProps = Pick<
  SettingsWorkbenchProps,
  "providerStatus" | "providerStatusError" | "statusError"
>

export function SettingsHero({
  providerStatus,
  providerStatusError,
  statusError,
}: SettingsHeroProps) {
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )

  return (
    <VpwSection aria-label="Workspace settings">
      <div className="flex flex-col gap-4 border-b border-[var(--vpw-border-default)] pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <p className="vpw-label text-[var(--vpw-teal)]">Settings console</p>
          <h2 className="mt-1 text-2xl font-semibold tracking-[-0.01em] text-[var(--vpw-text-primary)]">
            Workspace controls
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
            Local workspace defaults, provider state, and diagnostics.
          </p>
        </div>
        <div className="flex shrink-0">
          <Button asChild variant="outline">
            <Link to="/providers">View providers</Link>
          </Button>
        </div>
      </div>
      <div className="mt-3 flex min-w-0 flex-wrap gap-2">
        <SettingsHeroFact
          label="Workspace"
          tone="success"
          value="Local workspace"
        />
        <SettingsHeroFact
          label="Access"
          tone="info"
          value="Local single-user"
        />
        <SettingsHeroFact
          label="Snapshot"
          tone={provider.tone}
          value={providerStatus?.snapshot_mode ?? "loading"}
        />
        <SettingsHeroFact
          label="Evidence"
          tone={evidence.tone}
          value={evidence.label}
        />
      </div>
    </VpwSection>
  )
}

function SettingsHeroFact({
  label,
  tone,
  value,
}: {
  label: string
  tone: VpwBadgeTone
  value: string | number
}) {
  return (
    <div className="inline-flex min-w-0 items-center gap-2 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2 shadow-[var(--vpw-shadow-0)]">
      <p className="vpw-label">{label}</p>
      <div className="min-w-0">
        <VpwBadge tone={tone}>{value}</VpwBadge>
      </div>
    </div>
  )
}
