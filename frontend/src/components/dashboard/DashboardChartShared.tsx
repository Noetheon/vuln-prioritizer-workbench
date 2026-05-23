import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import type { ChartDatum } from "@/lib/chart-data"

export function ChartDataSummary({
  data,
  label,
}: {
  data: readonly ChartDatum[]
  label: string
}) {
  return (
    <Table containerClassName="sr-only">
      <TableCaption>{label}</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead scope="col">Signal</TableHead>
          <TableHead scope="col">Value</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((item) => (
          <TableRow key={item.label}>
            <TableHead scope="row">{item.label}</TableHead>
            <TableCell>{item.value}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export function riskToneFill(
  tone: ChartDatum["tone"],
  fallback = "var(--vpw-chart-risk)",
) {
  return tone === "critical"
    ? "var(--vpw-chart-critical)"
    : tone === "high"
      ? "var(--vpw-chart-high)"
      : tone === "medium"
        ? "var(--vpw-chart-medium)"
        : tone === "low"
          ? "var(--vpw-chart-low)"
          : fallback
}

export function priorityFill(tone: ChartDatum["tone"]) {
  return riskToneFill(tone, "var(--vpw-text-muted)")
}

export function epssFill(tone: ChartDatum["tone"]) {
  return riskToneFill(tone, "var(--vpw-chart-low)")
}

export function rankFill(index: number) {
  return `var(--vpw-chart-rank-${(index % 5) + 1})`
}

export const chartAxisTick = { fill: "var(--vpw-text-muted)", fontSize: 12 }

export const chartTooltipProps = {
  contentStyle: {
    background: "var(--vpw-bg-card)",
    border: "1px solid var(--vpw-border-default)",
    borderRadius: "var(--vpw-radius-md)",
    color: "var(--vpw-text-primary)",
  },
  cursor: {
    fill: "color-mix(in srgb, var(--vpw-blue) 7%, transparent)",
  },
  itemStyle: {
    color: "var(--vpw-text-primary)",
  },
  labelStyle: {
    color: "var(--vpw-text-secondary)",
    fontWeight: 600,
  },
}
