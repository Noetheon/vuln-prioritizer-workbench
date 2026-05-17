import {
  Activity,
  Database,
  Download,
  FileArchive,
  FileText,
  ShieldCheck,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { VpwAppFrame } from "./VpwAppFrame"
import { VpwBadge } from "./VpwBadge"
import { VpwBreadcrumbs } from "./VpwBreadcrumbs"
import { VpwChecksum } from "./VpwChecksum"
import { VpwCodeBlock } from "./VpwCodeBlock"
import { VpwDataTable, type VpwDataTableColumn } from "./VpwDataTable"
import { VpwDemoBanner } from "./VpwDemoBanner"
import { VpwEmptyState } from "./VpwEmptyState"
import { VpwEvidenceArtifactCard } from "./VpwEvidenceArtifactCard"
import { VpwEvidenceManifestCard } from "./VpwEvidenceManifestCard"
import { VpwExecutiveDecisionSummary } from "./VpwExecutiveDecisionSummary"
import { VpwField } from "./VpwField"
import { VpwFilterBar } from "./VpwFilterBar"
import {
  VpwElevationSpec,
  VpwSpacingSpec,
  VpwTypographySpec,
} from "./VpwFoundationSpecs"
import { VpwKeyValueList } from "./VpwKeyValueList"
import { VpwGrid, VpwPanel, VpwSection } from "./VpwLayout"
import { VpwMetricCard } from "./VpwMetricCard"
import { VpwPageContainer } from "./VpwPageContainer"
import { VpwProgress } from "./VpwProgress"
import {
  VpwAssetContextCard,
  VpwAttackTechniqueCard,
  VpwFindingSummaryCard,
  VpwWaiverDecisionCard,
} from "./VpwRiskComponents"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwSegmentedControl } from "./VpwSegmentedControl"
import { VpwSelectionCard } from "./VpwSelectionCard"
import { VpwSkeletonStack } from "./VpwSkeletonStack"
import { VpwStateBlock } from "./VpwStateBlock"
import { VpwStatusBanner } from "./VpwStatusBanner"
import { VpwTimeline } from "./VpwTimeline"
import { VpwTokenSwatch } from "./VpwTokenSwatch"
import { VpwToolbar, VpwToolbarGroup } from "./VpwToolbar"
import {
  VpwEvidenceFlowCard,
  VpwImportStepCard,
  VpwProviderSnapshotCard,
  VpwReportHistoryCard,
} from "./VpwWorkflowCards"

type ShowcaseFinding = {
  id: string
  priority: "critical" | "high" | "medium"
  evidence: string
  decision: string
}

const findingRows: ShowcaseFinding[] = [
  {
    id: "CVE-2024-3094",
    priority: "critical",
    evidence: "KEV, EPSS, asset exposure",
    decision: "Patch now",
  },
  {
    id: "CVE-2023-34362",
    priority: "high",
    evidence: "VEX occurrence evidence",
    decision: "Validate scope",
  },
  {
    id: "CVE-2021-44228",
    priority: "medium",
    evidence: "Provider snapshot",
    decision: "Monitor",
  },
]

const findingColumns: VpwDataTableColumn<ShowcaseFinding>[] = [
  {
    id: "id",
    header: "Finding",
    cell: (row) => <span className="font-mono text-xs">{row.id}</span>,
  },
  {
    id: "priority",
    header: "Priority",
    cell: (row) => (
      <VpwBadge tone={row.priority === "critical" ? "critical" : "warning"}>
        {row.priority}
      </VpwBadge>
    ),
  },
  { id: "evidence", header: "Evidence", cell: (row) => row.evidence },
  { id: "decision", header: "Decision", cell: (row) => row.decision },
]

export function VpwDesignSystemShowcase() {
  return (
    <VpwPageContainer className="flex flex-col gap-8">
      <VpwSectionHeader
        actions={<VpwBadge tone="info">Precision Light Analyst</VpwBadge>}
        description="Reusable VPW tokens, product components, controls, read/write evidence patterns and analyst product states."
        eyebrow="VPW Design System"
        title="Precision Light Analyst Design Set"
      />

      <VpwBreadcrumbs
        items={[
          { label: "VPW" },
          { label: "Design system" },
          { label: "Precision Light Analyst", current: true },
        ]}
      />

      <VpwAppFrame
        navItems={[
          { label: "Dashboard", icon: Activity, active: true },
          { label: "Findings", icon: ShieldCheck },
          { label: "Evidence Center", icon: FileArchive },
          { label: "Providers", icon: Database },
        ]}
        statusItems={[
          { label: "Provider", value: "Snapshot mode" },
          { label: "EPSS", value: "Fresh" },
          { label: "KEV", value: "Loaded" },
          { label: "Evidence", value: "Ready" },
        ]}
        title="Risk Operations"
      >
        <VpwGrid columns={4}>
          <VpwMetricCard label="Critical" tone="critical" value="12" />
          <VpwMetricCard label="KEV" tone="warning" value="5" />
          <VpwMetricCard label="Runs" tone="info" value="28" />
          <VpwMetricCard label="Evidence" tone="success" value="9" />
        </VpwGrid>
      </VpwAppFrame>

      <section className="grid gap-4 lg:grid-cols-4">
        <VpwMetricCard
          description="Open high-impact findings"
          icon={<ShieldCheck className="h-5 w-5" aria-hidden="true" />}
          label="Critical"
          tone="critical"
          value="12"
        />
        <VpwMetricCard
          description="Known exploited signals"
          icon={<Activity className="h-5 w-5" aria-hidden="true" />}
          label="KEV"
          tone="warning"
          value="5"
        />
        <VpwMetricCard
          description="Generated artifacts"
          icon={<FileArchive className="h-5 w-5" aria-hidden="true" />}
          label="Evidence"
          tone="success"
          value="9"
        />
        <VpwMetricCard
          description="Provider snapshot mode"
          icon={<Database className="h-5 w-5" aria-hidden="true" />}
          label="Providers"
          tone="info"
          value="Fresh"
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <div className="vpw-panel flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Token swatches are based on the installed kit variables."
            eyebrow="Foundations"
            title="Color and Surface Tokens"
          />
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <VpwTokenSwatch
              name="Ink"
              usage="Primary actions and product chrome"
              value="#171717"
            />
            <VpwTokenSwatch
              name="Link Blue"
              usage="Focus and informational states"
              value="#0070F3"
            />
            <VpwTokenSwatch
              name="Success"
              usage="Healthy and verified states"
              value="#047857"
            />
            <VpwTokenSwatch
              name="Critical"
              usage="Critical and destructive states"
              value="#C40000"
            />
          </div>
        </div>

        <div className="vpw-panel flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Toolbar, field wrappers and primitive controls."
            eyebrow="Controls"
            title="Forms and Actions"
          />
          <VpwToolbar label="Design system controls">
            <VpwToolbarGroup>
              <Button>
                <Download aria-hidden="true" data-icon="inline-start" />
                Generate report
              </Button>
              <Button variant="outline">Verify bundle</Button>
              <Button variant="ghost">Refresh</Button>
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <VpwBadge tone="success">Verified</VpwBadge>
              <VpwBadge tone="warning">Demo</VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
          <div className="grid gap-3 sm:grid-cols-2">
            <VpwField
              description="Used by imports, reports and waivers."
              label="Project"
            >
              <Input defaultValue="Payments Service" />
            </VpwField>
            <VpwField label="Priority">
              <Select defaultValue="critical">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                </SelectContent>
              </Select>
            </VpwField>
            <VpwField className="sm:col-span-2" label="Evidence note">
              <Textarea defaultValue="Reviewed provider snapshot, asset exposure, waiver state and evidence bundle readiness." />
            </VpwField>
          </div>
        </div>
      </section>

      <VpwGrid columns={3}>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Typography" title="Type Scale" />
          <VpwTypographySpec />
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Spacing" title="Rhythm and Radius" />
          <VpwSpacingSpec />
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Elevation" title="Shadow Scale" />
          <VpwElevationSpec />
        </VpwPanel>
      </VpwGrid>

      <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="flex flex-col gap-4">
          <VpwFilterBar
            actions={<Button variant="outline">Reset</Button>}
            searchPlaceholder="Search CVE, owner, service"
          >
            <VpwSegmentedControl
              label="Priority"
              options={[
                { label: "All", value: "all" },
                { label: "Critical", value: "critical" },
                { label: "KEV", value: "kev" },
              ]}
              value="critical"
            />
          </VpwFilterBar>
          <VpwDataTable
            caption="Design system findings table"
            columns={findingColumns}
            data={findingRows}
            density="standard"
            getRowKey={(row) => row.id}
          />
          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="attack">ATT&CK</TabsTrigger>
            </TabsList>
            <TabsContent value="overview">
              <VpwStatusBanner title="Prioritized queue ready" tone="success">
                Findings are ranked with provider, asset and waiver context.
              </VpwStatusBanner>
            </TabsContent>
            <TabsContent value="evidence">
              <VpwStatusBanner title="Evidence bundle ready" tone="info">
                Report artifacts can be generated for the selected run.
              </VpwStatusBanner>
            </TabsContent>
            <TabsContent value="attack">
              <VpwStatusBanner title="Defensive mapping only" tone="warning">
                ATT&CK context is shown only from reviewed mappings.
              </VpwStatusBanner>
            </TabsContent>
          </Tabs>
        </div>

        <div className="vpw-card flex flex-col gap-5 p-5">
          <VpwSectionHeader
            eyebrow="States"
            title="Product State Rules"
            description="Demo, empty, loading, success and error states share one token set."
          />
          <VpwDemoBanner>
            <strong>Demo preview</strong> - sample data only, not production
            evidence.
          </VpwDemoBanner>
          <VpwEmptyState
            description="Import project data to populate this queue."
            title="No findings yet"
          />
          <VpwSkeletonStack rows={3} />
        </div>
      </section>

      <VpwSection>
        <VpwSectionHeader
          eyebrow="Selection and state variants"
          title="Selectable Cards and State Blocks"
        />
        <VpwGrid columns={4}>
          <VpwSelectionCard
            checked
            meta="Current default"
            title="Snapshot mode"
          >
            Deterministic provider data for local evidence.
          </VpwSelectionCard>
          <VpwSelectionCard meta="Available" title="Live provider mode">
            Reserved for explicitly configured provider jobs.
          </VpwSelectionCard>
          <VpwStateBlock title="Report generated" tone="success">
            The evidence bundle is available for download.
          </VpwStateBlock>
          <VpwStateBlock title="Provider unavailable" tone="critical">
            Use the last known snapshot until the source is restored.
          </VpwStateBlock>
        </VpwGrid>
      </VpwSection>

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
          demo
          files={[
            { path: "reports/executive.html", label: "HTML" },
            { path: "reports/technical.md", label: "Markdown" },
            { path: "manifest.json", label: "JSON" },
          ]}
          generatedAt="2026-05-02 23:48"
          project="Payments Service"
          providerSources="NVD, EPSS, KEV"
          runId="demo-run-0001"
          verificationStatus="Demo preview"
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
          demo
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
          <VpwChecksum demo value="Demo preview - not a production checksum" />
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
    </VpwPageContainer>
  )
}
