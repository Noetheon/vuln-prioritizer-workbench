import { Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { VpwBadge, VpwDemoBanner } from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import {
  formatDisplayType,
  type ImportsWorkbenchProps,
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
  const selectedFormat = formatDisplayType(importWizard.inputType)

  return (
    <section className="imports-command-header" aria-labelledby="imports-title">
      <div className="imports-command-copy">
        <p className="imports-kicker">Imports</p>
        <h1 id="imports-title">Import security evidence</h1>
        <p>
          Normalize scanner, SBOM, and CVE-list inputs into prioritized
          findings.
        </p>
      </div>
      <div className="imports-command-status">
        <Metric
          label="Project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Selected" : "Required"}
        />
        <Metric
          label="Provider"
          tone={providerStatus?.status === "ok" ? "success" : "warning"}
          value={providerSummary?.value ?? "Checking"}
        />
        <Metric
          label="Runs"
          tone={projectRuns.length > 0 ? "info" : "neutral"}
          value={projectRuns.length}
        />
        <Metric
          label="Parser"
          tone={importWizard.file ? "success" : "neutral"}
          value={importWizard.file ? "File ready" : selectedFormat}
        />
      </div>
      <div className="imports-command-actions">
        {isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null}
        <Button asChild>
          <a href="#import-workflow">
            <Upload aria-hidden="true" data-icon="inline-start" />
            Start import
          </a>
        </Button>
      </div>
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Select or create a project before
          uploading production import files.
        </VpwDemoBanner>
      ) : null}
    </section>
  )
}

function Metric({
  label,
  tone,
  value,
}: {
  label: string
  tone: "critical" | "info" | "neutral" | "success" | "support" | "warning"
  value: string | number
}) {
  return (
    <div className="imports-command-metric">
      <span>{label}</span>
      <VpwBadge className="max-w-full truncate" tone={tone}>
        {value}
      </VpwBadge>
    </div>
  )
}
