import { Link } from "@/lib/router"

import { Button } from "@/components/ui/button"
import { VpwSection } from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsHeroProps = Pick<
  SettingsWorkbenchProps,
  "selectedProjectId"
>

export function SettingsHero({ selectedProjectId }: SettingsHeroProps) {
  return (
    <VpwSection aria-label="Workspace settings">
      <div className="flex flex-col gap-4 border-b border-[var(--vpw-border-default)] pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <p className="vpw-label text-[var(--vpw-teal)]">Settings console</p>
          <h2 className="mt-1 text-2xl font-semibold tracking-[-0.01em] text-[var(--vpw-text-primary)]">
            Workspace controls
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
            Local workspace defaults, provider state, and diagnostics.
          </p>
        </div>
        <div className="flex shrink-0">
          <Button asChild variant="outline">
            <Link
              search={selectedProjectRouteSearch(selectedProjectId)}
              to="/providers"
            >
              View providers
            </Link>
          </Button>
        </div>
      </div>
    </VpwSection>
  )
}
