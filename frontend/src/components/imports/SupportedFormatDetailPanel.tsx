import { Link } from "@/lib/router"
import { Button } from "@/components/ui/button"
import {
  MetaTag,
  VpwCodeBlock,
  VpwKeyValueList,
  VpwPanel,
} from "@/components/vpw"
import type { SupportedFormat } from "@/lib/import-format-metadata"
import { importFormatUrlSearch } from "@/workbench/import-route-search"
import { projectSearchString } from "./supported-formats-route-model"

type SupportedFormatDetailPanelProps = {
  format: SupportedFormat
  projectId: string
}

export function SupportedFormatDetailPanel({
  format,
  projectId,
}: SupportedFormatDetailPanelProps) {
  const search = importFormatUrlSearch(
    projectSearchString(projectId),
    format.inputType,
  )
  const copyExample = () => {
    void navigator.clipboard?.writeText(format.exampleSnippet)
  }

  return (
    <VpwPanel className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-[var(--vpw-text-primary)]">
          {format.label}
        </h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <MetaTag label={format.categoryLabel} />
          {format.extensions.map((extension) => (
            <MetaTag key={extension} label={extension} />
          ))}
        </div>
      </div>
      <VpwKeyValueList
        items={[
          { label: "About this format", value: format.shortDescription },
          { label: "Best for", value: format.bestFor },
          { label: "Expected shape", value: format.expectedShape },
          { label: "Minimum fields", value: format.minimumFields.join(", ") },
          {
            label: "Optional fields recognized",
            value:
              format.optionalFields.length > 0
                ? format.optionalFields.join(", ")
                : "None",
          },
          {
            label: "Context support",
            value: format.contextSupport.replaceAll("-", " "),
          },
        ]}
      />
      <VpwCodeBlock
        code={format.exampleSnippet}
        copyLabel="Copy example"
        label="Example snippet"
        onCopy={copyExample}
      />
      {format.notes.length > 0 ? (
        <div className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
          {format.notes.map((note) => (
            <p key={note}>{note}</p>
          ))}
        </div>
      ) : null}
      <Button asChild>
        <Link search={search} to="/imports/new">
          Start import with this format
        </Link>
      </Button>
    </VpwPanel>
  )
}
