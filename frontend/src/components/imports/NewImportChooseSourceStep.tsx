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
import { VpwSectionHeader } from "@/components/vpw"
import {
  FORMAT_CATEGORY_LABELS,
  SUPPORTED_IMPORT_FORMATS,
  type SupportedFormatCategory,
} from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import { FormatOptionCard } from "./NewImportSourceOption"

const categoryOrder: SupportedFormatCategory[] = [
  "simple",
  "scanner",
  "sbom",
  "network",
]

export function ChooseSourceStep({
  importWizard,
  onInputTypeChange,
  onProjectChange,
  projectListLoading,
  projects,
  selectedProjectId,
}: ImportsWorkbenchProps) {
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
      <div className="grid gap-5">
        {categoryOrder.map((category) => (
          <div className="grid gap-3" key={category}>
            <h3 className="text-sm font-semibold text-[var(--vpw-text-primary)]">
              {FORMAT_CATEGORY_LABELS[category]}
            </h3>
            <div className="grid gap-3 md:grid-cols-2">
              {SUPPORTED_IMPORT_FORMATS.filter(
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
