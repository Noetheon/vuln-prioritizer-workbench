import { FileText } from "lucide-react"

import { VpwChecksum } from "./VpwChecksum"
import { VpwCodeBlock } from "./VpwCodeBlock"
import { VpwEvidenceArtifactCard } from "./VpwEvidenceArtifactCard"
import { VpwEvidenceManifestCard } from "./VpwEvidenceManifestCard"
import { VpwExecutiveDecisionSummary } from "./VpwExecutiveDecisionSummary"
import { VpwKeyValueList } from "./VpwKeyValueList"
import { VpwGrid } from "./VpwLayout"
import { VpwProgress } from "./VpwProgress"
import {
  VpwAssetContextCard,
  VpwAttackTechniqueCard,
  VpwFindingSummaryCard,
  VpwWaiverDecisionCard,
} from "./VpwRiskComponents"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwTimeline } from "./VpwTimeline"
import {
  VpwEvidenceFlowCard,
  VpwImportStepCard,
  VpwProviderSnapshotCard,
  VpwReportHistoryCard,
} from "./VpwWorkflowCards"

export function VpwDesignSystemShowcaseEvidence() {
  return (
    <>
      <section className="grid gap-4 xl:grid-cols-3">
        <VpwEvidenceArtifactCard
          actionLabel="Generate Markdown"
          audience="Engineering"
          description="Technical report for analyst handoff and audit notes."
          format="Markdown"
          icon={<FileText className="h-4 w-4" aria-hidden="true" />}
          title="Technical Report"
        />
        <VpwEvidenceArtifactCard
          actionLabel="Build ZIP"
          audience="Audit"
          description="ZIP package with reports, manifest and checksum records."
          format="ZIP"
          title="Evidence Bundle"
        />
        <VpwEvidenceManifestCard
          files={[
            { path: "reports/executive.html", label: "HTML" },
            { path: "reports/technical.md", label: "Markdown" },
            { path: "manifest.json", label: "JSON" },
          ]}
          generatedAt="2026-05-02 23:48"
          project="Payments Service"
          providerSources="NVD, EPSS, KEV"
          runId="sample-run-0001"
          verificationStatus="Ready for verification"
        />
      </section>

      <VpwGrid columns={4}>
        <VpwFindingSummaryCard
          cveId="CVE-2024-3094"
          priority="Critical"
          signals={["KEV", "EPSS 94%", "Public asset"]}
          title="xz backdoor finding"
        />
        <VpwAssetContextCard
          asset="build-host-1"
          businessService="Payments"
          criticality="Critical"
          exposure="Public"
          owner="team-platform"
        />
        <VpwWaiverDecisionCard
          owner="risk-owner"
          reason="Temporary acceptance requires weekly review and evidence attachment."
          reviewDate="2026-05-10"
          status="In review"
        />
        <VpwAttackTechniqueCard
          tactic="Defense Evasion"
          technique="Reviewed ATT&CK context"
        />
      </VpwGrid>

      <VpwGrid columns={4}>
        <VpwImportStepCard
          description="CSV, SBOM and CVE list inputs normalize into the same evidence model."
          status="Ready"
          statusTone="success"
          title="Import wizard"
        />
        <VpwProviderSnapshotCard
          sources={[
            { name: "NVD", status: "fresh" },
            { name: "EPSS", status: "fresh" },
            { name: "KEV", status: "loaded" },
          ]}
        />
        <VpwReportHistoryCard
          rows={[
            {
              artifact: "executive.html",
              format: "HTML",
              generated: "May 3",
              status: "Ready",
            },
            {
              artifact: "bundle.zip",
              format: "ZIP",
              generated: "May 3",
              status: "Verified",
            },
          ]}
        />
        <VpwEvidenceFlowCard
          items={[
            { title: "Imported", tone: "success", meta: "09:30" },
            { title: "Prioritized", tone: "success", meta: "09:31" },
            { title: "Report review", tone: "warning", meta: "open" },
          ]}
        />
      </VpwGrid>

      <section className="grid gap-4 xl:grid-cols-2">
        <VpwExecutiveDecisionSummary
          businessImpact="Public-facing service exposure raises operational risk."
          decisionStatement="Approve immediate remediation for critical KEV findings and review accepted-risk waivers weekly."
          priority="Critical"
          problem="Known exploited vulnerabilities are present in priority services."
          recommendation="Patch exposed critical findings first, then generate evidence bundle."
        />
        <div className="vpw-card flex flex-col gap-5 p-5">
          <VpwSectionHeader
            eyebrow="Evidence flow"
            title="Timeline and Signal Strength"
          />
          <VpwTimeline
            items={[
              {
                title: "Import normalized",
                description: "CVE list and occurrence evidence accepted.",
                meta: "09:30",
                tone: "success",
              },
              {
                title: "Provider context attached",
                description: "NVD, EPSS and KEV snapshots matched.",
                meta: "09:31",
                tone: "success",
              },
              {
                title: "Waiver review needed",
                description: "Accepted-risk scope requires owner validation.",
                meta: "open",
                tone: "warning",
              },
            ]}
          />
          <VpwProgress label="Evidence readiness" tone="success" value={82} />
          <VpwProgress label="Residual risk" tone="critical" value={64} />
          <VpwChecksum value="sha256:sample-recorded-checksum" />
          <VpwCodeBlock
            code={`{
  "project": "Payments Service",
  "evidence": "ready",
  "provider_snapshot": "local"
}`}
            label="Manifest sample"
          />
          <VpwKeyValueList
            columns={2}
            items={[
              { label: "Container", value: "2400px max", tone: "info" },
              { label: "Density", value: "40px standard rows" },
              { label: "Radius", value: "4 / 6 / 8 / 8" },
              { label: "Overlay", value: "Shadow 3", tone: "support" },
            ]}
          />
        </div>
      </section>
    </>
  )
}
