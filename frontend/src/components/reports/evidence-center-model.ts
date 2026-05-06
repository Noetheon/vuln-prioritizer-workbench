import {
  FileArchive,
  FileJson,
  FileText,
  GitBranch,
  Table2,
  type LucideIcon,
} from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ReportVerificationPublic,
} from "@/api-client"
import { objectRecord } from "@/lib/app-errors"
import type { ReportFormat } from "@/lib/report-format"
import { runStatusTone } from "@/lib/risk-format"
import type { VpwBadgeTone, VpwMetricTone, VpwStatusBannerTone } from "@/components/vpw"

export type ArtifactCard = {
  actionLabel: string
  audience: string
  description: string
  format: string
  icon: LucideIcon
  reportFormat: ReportFormat
  title: string
}

export const ARTIFACT_CARDS: ArtifactCard[] = [
  {
    actionLabel: "Generate HTML",
    audience: "CISO",
    description:
      "Executive browser report with priority summary and evidence links.",
    format: "HTML",
    icon: FileText,
    reportFormat: "html",
    title: "Executive HTML Report",
  },
  {
    actionLabel: "Generate Markdown",
    audience: "Engineering",
    description: "Technical report for analyst handoff, PRs, and audit notes.",
    format: "Markdown",
    icon: FileText,
    reportFormat: "markdown",
    title: "Markdown Technical Report",
  },
  {
    actionLabel: "Export JSON",
    audience: "Automation",
    description:
      "Machine-readable findings and analysis data for downstream systems.",
    format: "JSON",
    icon: FileJson,
    reportFormat: "json",
    title: "JSON Findings Export",
  },
  {
    actionLabel: "Export CSV",
    audience: "Audit",
    description:
      "Spreadsheet-friendly findings table for triage and stakeholder review.",
    format: "CSV",
    icon: Table2,
    reportFormat: "csv",
    title: "CSV Findings Export",
  },
  {
    actionLabel: "Export Navigator",
    audience: "Security engineering",
    description:
      "ATT&CK Navigator JSON with mapped techniques and risk scores.",
    format: "Navigator JSON",
    icon: GitBranch,
    reportFormat: "attack-navigator",
    title: "ATT&CK Navigator Layer",
  },
  {
    actionLabel: "Export SARIF",
    audience: "CI",
    description:
      "SARIF 2.1.0 results for GitHub code scanning and CI evidence workflows.",
    format: "SARIF",
    icon: FileJson,
    reportFormat: "sarif",
    title: "SARIF Export",
  },
  {
    actionLabel: "Build Bundle",
    audience: "Evidence",
    description:
      "ZIP with all reports, manifest, source artifacts, and SHA256 checksums.",
    format: "Evidence ZIP",
    icon: FileArchive,
    reportFormat: "zip",
    title: "Evidence ZIP Bundle",
  },
]

export function runFileLabel(run: AnalysisRunPublic): string {
  const summaryJson = run.summary_json as Record<string, unknown> | undefined
  const inputUpload = summaryJson?.input_upload as
    | Record<string, unknown>
    | undefined
  const uploadFilename =
    typeof inputUpload?.filename === "string" ? inputUpload.filename : null
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}

export function priorityCount(
  summary: ProjectDecisionSummaryPublic | AnalysisRunSummaryPublic | null,
  key: "critical" | "high",
): number {
  return (summary?.counts_by_priority?.[key] ??
    summary?.counts_by_priority?.[key.charAt(0).toUpperCase() + key.slice(1)] ??
    0) as number
}

export function summaryOpenFindings(
  summary: ProjectDecisionSummaryPublic | AnalysisRunSummaryPublic | null,
): number {
  if (!summary) return 0
  if ("open_finding_count" in summary) {
    return summary.open_finding_count ?? 0
  }
  return summary.finding_count ?? 0
}

export function verificationSummary(report: ReportVerificationPublic | null) {
  return objectRecord(report?.summary)
}

export function runBadgeTone(
  status: AnalysisRunPublic["status"],
): VpwBadgeTone {
  const tone = runStatusTone(status)
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}

export function runMetricTone(
  run: AnalysisRunPublic | null,
  isDemo: boolean,
): VpwMetricTone {
  if (isDemo) return "success"
  if (!run) return "neutral"
  return runBadgeTone(run.status)
}

export function reportFormatTone(format: string): VpwBadgeTone {
  if (format === "zip") return "success"
  if (format === "html" || format === "markdown") return "info"
  if (format === "attack-navigator" || format === "sarif") return "support"
  return "neutral"
}

export function statusBannerTone(message: string): VpwStatusBannerTone {
  return message ? "success" : "info"
}
