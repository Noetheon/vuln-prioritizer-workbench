import { Button } from "@/components/ui/button"
import type { VpwDataTableColumn } from "@/components/vpw"
import type { SupportedFormat } from "@/lib/import-format-metadata"

type BuildSupportedFormatColumnsArgs = {
  onSelectInputType: (inputType: SupportedFormat["inputType"]) => void
  selectedInputType: SupportedFormat["inputType"]
}

export function buildSupportedFormatColumns({
  onSelectInputType,
  selectedInputType,
}: BuildSupportedFormatColumnsArgs): VpwDataTableColumn<SupportedFormat>[] {
  return [
    {
      id: "format",
      header: "Format",
      cell: (format) => (
        <Button
          className="text-left font-medium text-[var(--vpw-text-primary)] underline-offset-4 hover:underline"
          onClick={() => onSelectInputType(format.inputType)}
          size="sm"
          type="button"
          variant="link"
        >
          {format.label}
        </Button>
      ),
      width: "18%",
    },
    {
      id: "category",
      header: "Category",
      cell: (format) => format.categoryLabel,
      width: "13%",
    },
    {
      id: "extensions",
      header: "Extensions",
      cell: (format) => format.extensions.join(", "),
      width: "11%",
    },
    {
      id: "best",
      header: "Best for",
      cell: (format) => <SupportedFormatText value={format.bestFor} />,
      width: "20%",
    },
    {
      id: "shape",
      header: "Expected shape",
      cell: (format) => <SupportedFormatText value={format.expectedShape} />,
      width: "22%",
    },
    {
      id: "context",
      header: "Context support",
      cell: (format) => format.contextSupport.replaceAll("-", " "),
      width: "16%",
    },
    {
      id: "details",
      header: "Details",
      cell: (format) => (
        <Button
          className="w-full justify-center whitespace-nowrap px-2"
          onClick={() => onSelectInputType(format.inputType)}
          size="sm"
          type="button"
          variant={
            format.inputType === selectedInputType ? "secondary" : "outline"
          }
        >
          View details
        </Button>
      ),
      width: "128px",
    },
  ]
}

function SupportedFormatText({ value }: { value: string }) {
  return (
    <span
      className="line-clamp-2 max-w-[34rem] text-sm leading-5 text-[var(--vpw-text-secondary)]"
      title={value}
    >
      {value}
    </span>
  )
}
