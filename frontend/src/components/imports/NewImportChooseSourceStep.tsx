import { Link } from "@/lib/router"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { VpwSectionHeader, VpwStatusBanner } from "@/components/vpw"
import { supportedImportCategories } from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import { FormatOptionCard } from "./NewImportSourceOption"

export function ChooseSourceStep({
  capabilitiesError,
  capabilitiesLoading,
  importWizard,
  onInputTypeChange,
  onProjectChange,
  projectListLoading,
  projects,
  selectedProjectId,
  supportedFormats,
}: ImportsWorkbenchProps) {
  const categories = supportedImportCategories(supportedFormats)
  const projectDisabledReason = projectListLoading
    ? "Projects are loading."
    : projects.length === 0
      ? "No projects available."
      : ""
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        actions={
          <Button asChild size="sm" variant="outline">
            <Link
              search={selectedProjectRouteSearch(selectedProjectId)}
              to="/imports/formats"
            >
              Supported formats
            </Link>
          </Button>
        }
        description="Select the project and evidence format you want to import."
        title="Choose source"
      />
      <div className="grid gap-3">
        <label className="vpw-label" htmlFor="import-project">
          Project
        </label>
        <Select
          disabled={projectListLoading || projects.length === 0}
          name="importProject"
          onValueChange={onProjectChange}
          value={selectedProjectId}
        >
          <SelectTrigger
            aria-label="Import project"
            className="h-12"
            id="import-project"
          >
            <SelectValue placeholder="Select project" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {projects.map((project) => (
                <SelectItem key={project.id} value={project.id}>
                  {project.name}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        {projectDisabledReason ? (
          <p className="text-sm text-[var(--vpw-text-muted)]">
            {projectDisabledReason}
          </p>
        ) : null}
      </div>
      {capabilitiesError ? (
        <VpwStatusBanner title="Runtime capabilities unavailable" tone="critical">
          Import formats could not be loaded. Import actions are disabled.
        </VpwStatusBanner>
      ) : null}
      {!capabilitiesError && capabilitiesLoading ? (
        <VpwStatusBanner title="Loading runtime capabilities">
          Loading import formats from the Workbench backend.
        </VpwStatusBanner>
      ) : null}
      <div className="grid gap-5">
        {categories.map(({ category, label }) => (
          <div className="grid gap-3" key={category}>
            <h3 className="text-sm font-semibold text-[var(--vpw-text-primary)]">
              {label}
            </h3>
            <div className="grid gap-3 md:grid-cols-2">
              {supportedFormats.filter(
                (format) => format.category === category,
              ).map((format) => (
                <FormatOptionCard
                  checked={importWizard.inputType === format.inputType}
                  format={format}
                  key={format.inputType}
                  onClick={() => onInputTypeChange(format.inputType)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
