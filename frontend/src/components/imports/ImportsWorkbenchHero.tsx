import { CheckCircle2, History, PackageCheck, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDemoBanner,
  VpwGrid,
  VpwMetricCard,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { runStatusLabel } from "@/lib/risk-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import {
  formatDateTime,
  formatDisplayType,
  type ImportsWorkbenchProps,
  runFileLabel,
} from "./imports-workbench-model"

export function ImportHero({
  importWizard,
  projectListError,
  projectRuns,
  providerStatus,
  selectedProject,
}: Pick<
  ImportsWorkbenchProps,
  | "importWizard"
  | "projectListError"
  | "projectRuns"
  | "providerStatus"
  | "selectedProject"
>) {
  const providerSummary = providerStatus
    ? formatProviderFreshness(providerStatus)
    : null
  const isDemo = DEMO_MODE_ENABLED && !selectedProject && !projectListError
  const lastRun = projectRuns[0] ?? null

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <>
            {isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null}
            <Button asChild>
              <a href="#import-wizard">Upload evidence</a>
            </Button>
          </>
        }
        description="Bring supplied vulnerability evidence into the Workbench with a guided import flow."
        eyebrow="Imports"
        title="Imports"
      />
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Select or create a project before
          uploading production import files.
        </VpwDemoBanner>
      ) : null}
      <VpwGrid columns={4}>
        <VpwMetricCard
          description={selectedProject?.name ?? "No project selected"}
          icon={<PackageCheck aria-hidden="true" className="h-4 w-4" />}
          label="Current project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Ready" : "Required"}
        />
        <VpwMetricCard
          description={providerSummary?.detail ?? "Provider status loading"}
          icon={<CheckCircle2 aria-hidden="true" className="h-4 w-4" />}
          label="Provider snapshot"
          tone={providerStatus?.status === "ok" ? "success" : "info"}
          value={providerSummary?.value ?? "Checking"}
        />
        <VpwMetricCard
          description={
            lastRun
              ? `${runFileLabel(lastRun)} · ${formatDateTime(lastRun.started_at)}`
              : "No run recorded yet"
          }
          icon={<History aria-hidden="true" className="h-4 w-4" />}
          label="Last import run"
          tone="info"
          value={lastRun ? runStatusLabel(lastRun.status) : "No runs"}
        />
        <VpwMetricCard
          description={formatDisplayType(importWizard.inputType)}
          icon={<Upload aria-hidden="true" className="h-4 w-4" />}
          label="Selected format"
          tone={importWizard.file ? "success" : "neutral"}
          value={importWizard.file ? "File ready" : "Waiting"}
        />
      </VpwGrid>
    </VpwSection>
  )
}
