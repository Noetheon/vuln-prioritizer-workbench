import type {
  AnalysisRunPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import {
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwTimeline,
  type VpwTimelineItem,
} from "@/components/vpw"
import {
  evidenceBundleReport,
  verificationSummary,
} from "./evidence-center-model"

type EvidenceLifecycleProps = {
  activeReportFormat: string
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  reportsLoading: boolean
  selectedReportRun: AnalysisRunPublic | null
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

export function EvidenceLifecycle({
  activeReportFormat,
  reportActionsEnabled,
  reports,
  reportsLoading,
  selectedReportRun,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: EvidenceLifecycleProps) {
  const effectiveReports = reports
  const zipReport = evidenceBundleReport(effectiveReports)
  const verificationTargetsZip = Boolean(
    zipReport && verificationReportTarget?.id === zipReport.id,
  )
  const verifiedSummary = verificationTargetsZip
    ? verificationSummary(verificationReport)
    : {}
  const verificationOk = verificationTargetsZip && verifiedSummary.ok === true
  const verificationFailed = Boolean(
    verificationTargetsZip && verificationReport && verifiedSummary.ok !== true,
  )
  const artifactsGenerated = effectiveReports.length > 0
  const lifecycle: VpwTimelineItem[] = [
    {
      description: selectedReportRun
        ? "A run is selected and anchors generated artifacts."
        : "Select a completed import run before generating evidence.",
      meta: selectedReportRun ? "Done" : "Pending",
      title: "1. Run selected",
      tone: selectedReportRun ? "success" : "neutral",
    },
    {
      description: activeReportFormat
        ? "Artifact generation is currently running."
        : artifactsGenerated
          ? `${effectiveReports.length} artifacts are available.`
          : "Generate at least one artifact for this run.",
      meta: activeReportFormat
        ? "Current"
        : artifactsGenerated
          ? `Done · ${effectiveReports.length} artifacts`
          : reportsLoading
            ? "Loading"
            : "Pending",
      title: "2. Artifacts generated",
      tone: activeReportFormat
        ? "warning"
        : artifactsGenerated
          ? "success"
          : reportActionsEnabled
            ? "warning"
            : "neutral",
    },
    {
      description: zipReport
        ? "Evidence ZIP is available for audit packaging."
        : "Build the Evidence ZIP to include manifest and checksums.",
      meta: zipReport ? `Done · ${zipReport.filename}` : "Pending",
      title: "3. Bundle built",
      tone: zipReport ? "success" : "neutral",
    },
    {
      description: verificationOk
        ? "SHA256 values match the manifest."
        : verificationFailed
          ? "Checksum drift was detected. Rebuild the bundle or inspect manifest details."
          : zipReport
            ? "Verify the bundle before audit use."
            : "Build the Evidence ZIP first.",
      meta: verificationLoading
        ? "Current"
        : verificationOk
          ? "Verified"
          : verificationFailed
            ? "Failed"
            : "Pending",
      title: "4. Bundle verified",
      tone: verificationFailed
        ? "critical"
        : verificationOk
          ? "success"
          : zipReport || verificationLoading
            ? "warning"
            : "neutral",
    },
    {
      description: verificationOk
        ? "Evidence package is ready for audit use."
        : "Finish bundle generation and verification before audit use.",
      meta: verificationOk ? "Ready" : "Pending",
      title: "5. Ready for audit use",
      tone: verificationOk ? "success" : "neutral",
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Run selection, artifact generation, bundle build, verification, and audit readiness."
        title="Evidence lifecycle"
      />
      <VpwPanel className="p-5">
        <VpwTimeline items={lifecycle} />
      </VpwPanel>
    </VpwSection>
  )
}
