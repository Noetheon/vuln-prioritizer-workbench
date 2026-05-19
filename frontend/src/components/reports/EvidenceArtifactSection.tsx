import {
  VpwBadge,
  VpwEvidenceArtifactCard,
  VpwGrid,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ReportFormat } from "@/lib/report-format"
import { ARTIFACT_CARDS } from "./evidence-center-model"

type ArtifactSectionProps = {
  activeReportFormat: string
  isDemo: boolean
  reportActionsEnabled: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
}

export function ArtifactSection({
  activeReportFormat,
  isDemo,
  onCreateReport,
  reportActionsEnabled,
}: ArtifactSectionProps) {
  return (
    <VpwSection id="evidence-artifacts">
      <VpwSectionHeader
        actions={
          isDemo ? (
            <VpwBadge tone="warning">Generation disabled</VpwBadge>
          ) : null
        }
        description={
          reportActionsEnabled
            ? "Select a format to generate an artifact for the selected run."
            : isDemo
              ? "Demo artifacts are preview-only. Connect a real completed run to enable generation."
              : "Select a completed run to enable generation."
        }
        title="Generate Evidence Artifacts"
      />
      <VpwGrid columns={4}>
        {ARTIFACT_CARDS.map((card) => {
          const Icon = card.icon
          const isActive = activeReportFormat === card.reportFormat
          return (
            <VpwEvidenceArtifactCard
              actionLabel={isActive ? "Generating..." : card.actionLabel}
              audience={card.audience}
              busy={isActive}
              description={card.description}
              disabled={!reportActionsEnabled || isActive}
              format={card.format}
              icon={<Icon aria-hidden="true" className="h-4 w-4" />}
              key={card.reportFormat}
              onAction={() => void onCreateReport(card.reportFormat)}
              title={card.title}
            />
          )
        })}
      </VpwGrid>
    </VpwSection>
  )
}
