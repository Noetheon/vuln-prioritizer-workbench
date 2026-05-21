import type {
  AnalysisRunPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwEvidenceManifestCard,
  VpwSection,
  VpwStatusBanner,
} from "@/components/vpw"
import { DEMO_PROJECT, DEMO_REPORTS, DEMO_RUNS } from "@/lib/demo-data"
import { formatReportDateTime, reportFormatLabel } from "@/lib/report-format"
import { verificationSummary } from "./evidence-center-model"

type ManifestProps = {
  selectedProject: ProjectPublic | null
  selectedReportRun: AnalysisRunPublic | null
  reports: ReportPublic[]
  providerStatus: ProviderStatusPublic | null
  isDemo: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
}

export function ManifestPreview({
  isDemo,
  onDownload,
  onVerify,
  providerStatus,
  reports,
  selectedProject,
  selectedReportRun,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: ManifestProps) {
  const project = isDemo ? DEMO_PROJECT : selectedProject
  const run = isDemo ? DEMO_RUNS[0] : selectedReportRun
  const effectiveReports = isDemo ? DEMO_REPORTS : reports
  const zipReport = effectiveReports.find((report) => report.format === "zip")
  const providerSources =
    providerStatus?.snapshot.selected_sources?.join(", ") ??
    (isDemo ? "nvd, epss, kev" : "Unavailable")
  const checksumStatus = isDemo
    ? "Demo preview - not real checksums"
    : zipReport?.sha256
      ? zipReport.sha256
      : "Not generated yet"
  const matchesVerifiedBundle =
    Boolean(zipReport) && verificationReportTarget?.id === zipReport?.id
  const verifiedSummary = matchesVerifiedBundle
    ? verificationSummary(verificationReport)
    : {}
  const verifiedFiles = Number(verifiedSummary.verified_files ?? 0)
  const modifiedFiles = Number(verifiedSummary.modified_files ?? 0)
  const missingFiles = Number(verifiedSummary.missing_files ?? 0)
  const verificationStatus = isDemo
    ? "Demo preview"
    : matchesVerifiedBundle && verificationLoading
      ? "Verification running"
      : matchesVerifiedBundle &&
          verificationReport &&
          verifiedSummary.ok === true
        ? `Verified - ${verifiedFiles} files matched`
        : matchesVerifiedBundle && verificationReport
          ? `Verification failed - ${modifiedFiles} modified, ${missingFiles} missing`
          : zipReport
            ? "Ready for verification"
            : "Not generated yet"
  const verificationTone =
    verificationStatus.startsWith("Verified")
      ? "success"
      : verificationStatus.startsWith("Verification failed")
        ? "critical"
        : zipReport
          ? "warning"
          : "info"

  return (
    <VpwSection>
      <VpwStatusBanner
        action={
          zipReport && !isDemo ? (
            <Button
              aria-busy={verificationLoading}
              disabled={verificationLoading}
              onClick={() => onVerify(zipReport)}
              type="button"
              variant="outline"
            >
              Verify bundle
            </Button>
          ) : null
        }
        title="Bundle verification"
        tone={verificationTone}
      >
        {verificationStatus}
      </VpwStatusBanner>
      <VpwEvidenceManifestCard
        checksumStatus={checksumStatus}
        className="h-full"
        demo={isDemo}
        downloadDisabled={isDemo || !zipReport}
        downloadLabel={
          isDemo
            ? "Demo manifest"
            : zipReport
              ? "Download Evidence ZIP"
              : "Generate ZIP first"
        }
        files={effectiveReports.map((report) => ({
          label: reportFormatLabel(report.format),
          path: report.filename,
        }))}
        generatedAt={
          zipReport
            ? formatReportDateTime(zipReport.created_at)
            : "Not generated yet"
        }
        onDownload={
          !isDemo && zipReport ? () => onDownload(zipReport) : undefined
        }
        project={project?.name ?? "None selected"}
        providerSources={providerSources}
        runId={run ? run.id : "Not selected"}
        verificationStatus={verificationStatus}
      />
    </VpwSection>
  )
}
