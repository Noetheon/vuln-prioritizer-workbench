import {
  FileArchive,
  FileJson,
  FileText,
  GitBranch,
  Table2,
  type LucideIcon,
} from "lucide-react"
import type { ReportFormatCapabilityPublic } from "../api-client"
import type { ReportFormat } from "./report-format.ts"

export type ArtifactCard = {
  actionLabel: string
  audience: string
  contentType: string
  description: string
  filename: string
  format: string
  icon: LucideIcon
  kind: string
  reportFormat: ReportFormat
  title: string
}

const REPORT_FORMAT_ICONS: Partial<Record<string, LucideIcon>> = {
  "attack-navigator": GitBranch,
  csv: Table2,
  html: FileText,
  json: FileJson,
  markdown: FileText,
  sarif: FileJson,
  zip: FileArchive,
}

const RECOMMENDED_ARTIFACT_FORMATS = [
  "zip",
  "html",
  "markdown",
] as const

export function artifactCardsFromCapabilities(
  capabilities: readonly ReportFormatCapabilityPublic[],
): ArtifactCard[] {
  return capabilities.map((capability) => ({
    actionLabel: capability.action_label,
    audience: capability.audience,
    contentType: capability.content_type,
    description: capability.detail,
    filename: capability.filename,
    format: capability.label,
    icon: REPORT_FORMAT_ICONS[capability.format] ?? FileText,
    kind: capability.kind,
    reportFormat: capability.format as ReportFormat,
    title: capability.title,
  }))
}

export function recommendedArtifactCards(cards: readonly ArtifactCard[]) {
  return RECOMMENDED_ARTIFACT_FORMATS.map((format) =>
    artifactCardForFormat(cards, format),
  ).filter((card): card is ArtifactCard => Boolean(card))
}

export function additionalArtifactCards(cards: readonly ArtifactCard[]) {
  const recommended = new Set<string>(RECOMMENDED_ARTIFACT_FORMATS)
  return cards.filter((card) => !recommended.has(card.reportFormat))
}

export function artifactCardForFormat(
  cards: readonly ArtifactCard[],
  format: string,
) {
  return cards.find((item) => item.reportFormat === format) ?? null
}

export function requireArtifactCardForFormat(
  cards: readonly ArtifactCard[],
  format: ReportFormat,
) {
  const card = artifactCardForFormat(cards, format)
  if (card === null) {
    throw new Error(`Report format capability missing for ${format}`)
  }
  return card
}
