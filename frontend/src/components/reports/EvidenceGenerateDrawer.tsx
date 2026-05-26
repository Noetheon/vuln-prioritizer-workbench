import { useEffect, useMemo, useState } from "react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DetailDrawer,
  StatusLozenge,
  VpwBadge,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  type ArtifactCard,
  artifactCardForFormat,
} from "@/lib/report-capability-catalog"
import type { ReportFormat } from "@/lib/report-format"
import { runStatusLabel } from "@/lib/risk-format"
import {
  attackNavigatorAvailable,
  generatedActionLabel,
  providerSnapshotShortId,
  reportForFormat,
  runShortId,
  summaryOpenFindings,
} from "./evidence-center-model"

type EvidenceGenerateDrawerProps = {
  activeReportFormat: string
  onCreateReport: (format: ReportFormat) => Promise<void>
  onOpenChange: (open: boolean) => void
  open: boolean
  project: ProjectPublic | null
  providerStatus: ProviderStatusPublic | null
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  artifactCards: readonly ArtifactCard[]
}

export function EvidenceGenerateDrawer({
  activeReportFormat,
  onCreateReport,
  onOpenChange,
  open,
  project,
  providerStatus,
  reportActionsEnabled,
  reports,
  selectedReportRun,
  selectedRunSummary,
  artifactCards,
}: EvidenceGenerateDrawerProps) {
  const attackAvailable = attackNavigatorAvailable(
    selectedRunSummary,
    selectedReportRun,
  )
  const firstAvailableFormat = useMemo(
    () =>
      artifactCards.find(
        (card) => card.reportFormat !== "attack-navigator" || attackAvailable,
      )?.reportFormat ?? "",
    [artifactCards, attackAvailable],
  )
  const [selectedFormat, setSelectedFormat] =
    useState<ReportFormat | "">(firstAvailableFormat)
  const selectedCard = selectedFormat
    ? artifactCardForFormat(artifactCards, selectedFormat)
    : null
  const selectedReport = selectedFormat
    ? reportForFormat(reports, selectedFormat)
    : null
  const canGenerate =
    reportActionsEnabled &&
    !activeReportFormat &&
    Boolean(selectedFormat) &&
    (selectedFormat !== "attack-navigator" || attackAvailable)

  useEffect(() => {
    if (!selectedFormat || !artifactCardForFormat(artifactCards, selectedFormat)) {
      setSelectedFormat(firstAvailableFormat)
    }
  }, [artifactCards, firstAvailableFormat, selectedFormat])

  async function submitSelection() {
    if (!canGenerate || !selectedFormat) return
    await onCreateReport(selectedFormat)
    onOpenChange(false)
  }

  return (
    <DetailDrawer
      className="w-[min(100vw,46rem)] sm:max-w-none"
      description={`Create reports and evidence artifacts for run ${runShortId(selectedReportRun)}.`}
      footer={
        <div className="flex w-full flex-wrap justify-end gap-2">
          <Button
            onClick={() => onOpenChange(false)}
            type="button"
            variant="outline"
          >
            Cancel
          </Button>
          <Button
            aria-busy={activeReportFormat === selectedFormat}
            disabled={!canGenerate}
            onClick={() => void submitSelection()}
            type="button"
          >
            {activeReportFormat === selectedFormat
              ? "Generating"
              : generatedActionLabel(selectedCard, selectedReport)}
          </Button>
        </div>
      }
      onOpenChange={onOpenChange}
      open={open}
      title="Generate evidence"
    >
      <div className="flex flex-col gap-5">
        <VpwPanel className="p-4">
          <VpwSectionHeader
            description="The selected run anchors every generated artifact."
            eyebrow="Run context"
            title="Run context"
          />
          <VpwKeyValueList
            columns={2}
            density="compact"
            items={[
              {
                label: "Project",
                value: project?.name ?? "No project selected",
              },
              {
                label: "Run ID",
                value: selectedReportRun?.id ?? "No run selected",
                description: selectedReportRun
                  ? runStatusLabel(selectedReportRun.status)
                  : "Select a completed run",
              },
              {
                label: "Findings in scope",
                value: summaryOpenFindings(selectedRunSummary),
              },
              {
                label: "Provider snapshot",
                value: providerSnapshotShortId(
                  selectedReportRun,
                  providerStatus,
                ),
              },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-4">
          <VpwSectionHeader
            description="Choose one artifact type. Existing artifacts can be regenerated."
            eyebrow="Artifact type"
            title="Choose artifact type"
          />
          <VpwGrid columns={1}>
            {artifactCards.map((card) => {
              const format = card.reportFormat
              const existing = reportForFormat(reports, format)
              const unavailable =
                format === "attack-navigator" && !attackAvailable
              return (
                <Button
                  aria-pressed={selectedFormat === format}
                  className="h-auto w-full justify-start whitespace-normal rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3 text-left transition hover:border-[var(--vpw-border-strong)] data-[selected=true]:border-[var(--vpw-text-primary)]"
                  data-selected={selectedFormat === format}
                  disabled={unavailable}
                  key={format}
                  onClick={() => setSelectedFormat(format)}
                  type="button"
                  variant="ghost"
                >
                  <span className="flex flex-wrap items-start justify-between gap-3">
                    <span>
                      <span className="block text-sm font-semibold text-[var(--vpw-text-primary)]">
                        {card.title}
                      </span>
                      <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
                        {unavailable
                          ? "Available only when mapped ATT&CK context exists."
                          : card.description}
                      </span>
                    </span>
                    <span className="flex flex-wrap gap-2">
                      <VpwBadge>{card.format}</VpwBadge>
                      <StatusLozenge
                        density="compact"
                        label={existing ? "Generated" : "Missing"}
                        status={existing ? "succeeded" : "unknown"}
                      />
                    </span>
                  </span>
                </Button>
              )
            })}
          </VpwGrid>
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-4">
          <VpwSectionHeader eyebrow="Options" title="Options" />
          <DrawerOption checked label="Include provider snapshot metadata" />
          <DrawerOption checked label="Include accepted-risk evidence" />
          <DrawerOption
            checked={attackAvailable}
            disabled={!attackAvailable}
            label="Include ATT&CK Navigator layer when available"
          />
          <DrawerOption
            checked={Boolean(selectedReport)}
            label="Replace existing artifact if already generated"
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-4">
          <VpwSectionHeader eyebrow="Readiness" title="Readiness checklist" />
          <VpwKeyValueList
            columns={2}
            density="compact"
            items={[
              {
                label: "Run succeeded",
                tone:
                  selectedReportRun?.status === "succeeded"
                    ? "success"
                    : "warning",
                value: selectedReportRun
                  ? runStatusLabel(selectedReportRun.status)
                  : "No run",
              },
              {
                label: "Findings in scope",
                tone:
                  summaryOpenFindings(selectedRunSummary) > 0
                    ? "success"
                    : "warning",
                value: summaryOpenFindings(selectedRunSummary),
              },
              {
                label: "Provider snapshot",
                tone: selectedReportRun?.provider_snapshot_id
                  ? "success"
                  : "warning",
                value: providerSnapshotShortId(
                  selectedReportRun,
                  providerStatus,
                ),
              },
              {
                label: "Parser errors",
                tone:
                  (selectedRunSummary?.parse_errors?.length ?? 0) > 0
                    ? "warning"
                    : "success",
                value: selectedRunSummary?.parse_errors?.length ?? 0,
              },
            ]}
          />
        </VpwPanel>
      </div>
    </DetailDrawer>
  )
}

function DrawerOption({
  checked,
  disabled,
  label,
}: {
  checked: boolean
  disabled?: boolean
  label: string
}) {
  return (
    <div className="flex items-center gap-2 text-sm text-[var(--vpw-text-secondary)]">
      <Checkbox aria-label={label} checked={checked} disabled={disabled} />
      <span>{label}</span>
    </div>
  )
}
