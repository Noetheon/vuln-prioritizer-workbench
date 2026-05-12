import { stringValue } from "@/lib/app-errors"
import { formatLabel as labelize } from "@/lib/ui-copy"

import type { FindingAttackContext } from "./finding-detail-shared"

export function attackTechniqueRows(context: FindingAttackContext | null) {
  if (!context) {
    return []
  }
  const techniques = context.techniques ?? []
  if (techniques.length > 0) {
    return techniques
  }
  return (context.mappings ?? []).map((mapping) => ({
    confidence: mapping.confidence,
    defensive_note: mapping.defensive_note,
    name: mapping.technique_name,
    rationale: mapping.rationale,
    review_status: mapping.review_status,
    source: mapping.source,
    tactics: mapping.tactics ?? [],
    technique_id: mapping.technique_id,
    url: null,
  }))
}

export function attackTacticsLabel(values: string[] | null | undefined) {
  return values && values.length > 0 ? values.join(", ") : "Not mapped"
}

export function attackConfidenceLabel(value: string | null | undefined) {
  return value ? labelize(value) : "Unknown"
}

export function attackSourceLabel(
  source: string | null | undefined,
  context: FindingAttackContext | null,
) {
  const references = (context?.mappings ?? []).flatMap(
    (mapping) => mapping.references ?? [],
  )
  if (
    references.some((reference) =>
      reference.toLowerCase().includes("local curated demo mapping"),
    )
  ) {
    return "Local curated demo mapping"
  }
  if (source === "local-curated") {
    return "Local curated mapping"
  }
  return source ?? null
}

export function attackCoverageStatusLabel(
  context: FindingAttackContext | null,
) {
  const note = (stringValue(context?.defensive_note) ?? "").toLowerCase()
  if (!note) {
    return "Not recorded"
  }
  if (/partial|unknown/.test(note)) {
    return "Partial / unknown"
  }
  if (/gap|missing|validate|coverage|detect/.test(note)) {
    return "Needs validation"
  }
  return "Recorded"
}

export function defensiveActionItems(value: string | null | undefined) {
  return (value ?? "")
    .split(/\n+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function attackContextEmptyState(context: FindingAttackContext | null) {
  return (
    !context ||
    context.mapped !== true ||
    attackTechniqueRows(context).length === 0
  )
}
