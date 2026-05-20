import type { ReactNode } from "react"

import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwEvidenceFlowCard,
  VpwGrid,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { providerDataQualityNotes } from "@/lib/provider-format"
import {
  buildProviderEvidenceFlowItems,
  evidenceReadinessFullLabel,
  type ProviderSourceCounts,
} from "./providers-workbench-model"

type ProviderDataQualitySectionProps = {
  counts: ProviderSourceCounts
  providerStatus: ProviderStatusPublic | null
}

function QualityNote({
  children,
  title,
  tone = "info",
}: {
  children: ReactNode
  title: string
  tone?: "info" | "success" | "warning" | "critical"
}) {
  const toneClass = {
    critical: "border-l-[var(--vpw-red)]",
    info: "border-l-[var(--vpw-blue)]",
    success: "border-l-[var(--vpw-green)]",
    warning: "border-l-[var(--vpw-amber)]",
  }[tone]

  return (
    <div
      className={`rounded-[var(--vpw-radius-lg)] border border-l-2 border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-4 py-3 ${toneClass}`}
    >
      <h3 className="text-sm font-semibold text-[var(--vpw-text-primary)]">
        {title}
      </h3>
      <p className="mt-1 text-sm leading-6 text-[var(--vpw-text-secondary)]">
        {children}
      </p>
    </div>
  )
}

function ProviderDataQualityNotes({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  const warnings = providerStatus?.warnings ?? []
  const derivedNotes = providerDataQualityNotes(providerStatus)

  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Operational warnings and interpretation rules for provider signals."
        eyebrow="Provider data quality"
        title="Provider data quality notes"
      />
      <section className="flex flex-col gap-3" aria-labelledby="provider-active-warnings">
        <h3
          className="text-sm font-semibold text-[var(--vpw-text-primary)]"
          id="provider-active-warnings"
        >
          Active warnings
        </h3>
        {warnings.length > 0 ? (
          warnings.map((warning) => (
            <QualityNote key={warning} title="Provider warning" tone="warning">
              {warning}
            </QualityNote>
          ))
        ) : (
          <QualityNote title="No warnings" tone="success">
            No provider warnings or last-error state recorded.
          </QualityNote>
        )}
        {providerStatus?.last_error ? (
          <QualityNote title="Last provider error" tone="critical">
            {providerStatus.last_error}
          </QualityNote>
        ) : null}
      </section>

      <section
        className="flex flex-col gap-3"
        aria-labelledby="provider-interpretation-rules"
      >
        <h3
          className="text-sm font-semibold text-[var(--vpw-text-primary)]"
          id="provider-interpretation-rules"
        >
          Source interpretation rules
        </h3>
        <QualityNote title="CVSS coverage" tone="info">
          CVSS is impact and severity evidence, not exploit probability.
        </QualityNote>
        <QualityNote title="EPSS coverage" tone="warning">
          EPSS is exploit probability evidence, not impact severity. Missing
          EPSS means incomplete probability evidence, not zero likelihood.
        </QualityNote>
        <QualityNote title="KEV signal" tone="critical">
          KEV is a strong known-exploited prioritization signal when present.
        </QualityNote>
        <QualityNote title="Missing provider evidence" tone="warning">
          Missing provider evidence should be shown as incomplete, not as zero
          risk.
        </QualityNote>
      </section>

      <section
        className="flex flex-col gap-3"
        aria-labelledby="provider-snapshot-notes"
      >
        <h3
          className="text-sm font-semibold text-[var(--vpw-text-primary)]"
          id="provider-snapshot-notes"
        >
          Snapshot and evidence notes
        </h3>
        <QualityNote title="Locked snapshots" tone="success">
          Locked snapshots support reproducible reports and evidence bundles.
        </QualityNote>
        {derivedNotes.map((note) => (
          <QualityNote key={note} title="Snapshot note" tone="info">
            {note}
          </QualityNote>
        ))}
      </section>
    </VpwPanel>
  )
}

export function ProviderDataQualitySection({
  counts,
  providerStatus,
}: ProviderDataQualitySectionProps) {
  const evidenceReadiness = evidenceReadinessFullLabel(providerStatus)
  const evidenceFlowItems = buildProviderEvidenceFlowItems({
    availableSources: counts.availableSources,
    evidenceReadiness,
    missingSources: counts.missingSources,
    providerStatus,
  })

  return (
    <VpwSection>
      <VpwGrid columns={2}>
        <ProviderDataQualityNotes providerStatus={providerStatus} />
        <div className="flex min-w-0 flex-col gap-4">
          <VpwEvidenceFlowCard items={evidenceFlowItems} />
          <VpwStatusBanner title="Provider data boundary" tone="info">
            Provider data supports prioritization and reporting. It does not
            scan systems, provide attack instructions, or prove local
            compromise.
          </VpwStatusBanner>
        </div>
      </VpwGrid>
    </VpwSection>
  )
}
