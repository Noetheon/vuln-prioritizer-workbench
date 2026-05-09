import { CheckCircle2, History, PackageCheck, Upload } from "lucide-react"
import {
  VpwBadge,
  VpwDemoBanner,
  VpwGrid,
  VpwMetricCard,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import {
  formatDisplayType,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

export function ImportHero({
  importWizard,
  projectRuns,
  providerStatus,
  selectedProject,
}: Pick<
  ImportsWorkbenchProps,
  "importWizard" | "projectRuns" | "providerStatus" | "selectedProject"
>) {
  const providerSummary = providerStatus
    ? formatProviderFreshness(providerStatus)
    : null
  const isDemo = DEMO_MODE_ENABLED && !selectedProject

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null
        }
        description="Normalize scanner, SBOM, and CVE-list inputs into prioritized findings."
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
          description="Historical import runs"
          icon={<History aria-hidden="true" className="h-4 w-4" />}
          label="Run history"
          tone="info"
          value={projectRuns.length}
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
