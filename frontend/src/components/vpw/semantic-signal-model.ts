import type { VpwBadgeTone } from "./VpwBadge"
import {
  normalizeSemanticToken,
  type SignalKind,
} from "./semantic-badge-types.ts"

const signalTones: Record<SignalKind, VpwBadgeTone> = {
  attack: "support",
  cvss: "info",
  epss: "info",
  kev: "critical",
  provider: "info",
  unknown: "neutral",
  vex: "support",
}

function formattedPercent(value: number) {
  return `${Math.round(value * 1000) / 10}%`
}

function formattedSignalValue(value: string | number | null | undefined) {
  if (typeof value === "number") return value.toFixed(1)
  if (typeof value === "string" && value.trim()) return value
  return null
}

export function normalizeSignalKind(
  kind: SignalKind | string | null | undefined,
): SignalKind {
  switch (normalizeSemanticToken(kind)) {
    case "_epss":
    case "epss":
      return "epss"
    case "attack":
    case "attack_mapped":
    case "ttp":
      return "attack"
    case "cvss":
      return "cvss"
    case "kev":
      return "kev"
    case "provider":
    case "source":
      return "provider"
    case "vex":
      return "vex"
    default:
      return "unknown"
  }
}

export function signalTone(kind: SignalKind | string | null | undefined) {
  return signalTones[normalizeSignalKind(kind)]
}

export function signalLabel({
  kind,
  value,
}: {
  kind: SignalKind | string | null | undefined
  value?: string | number | null
}) {
  const normalized = normalizeSignalKind(kind)
  if (normalized === "epss" && typeof value === "number") {
    return `EPSS ${formattedPercent(value)}`
  }
  if (normalized === "cvss") {
    const formatted = formattedSignalValue(value)
    return formatted ? `CVSS ${formatted}` : "CVSS"
  }
  if (normalized === "provider") {
    const formatted = formattedSignalValue(value)
    return formatted ? `Provider ${formatted}` : "Provider"
  }
  if (normalized === "attack") return "ATT&CK mapped"
  if (normalized === "kev") return "KEV"
  if (normalized === "vex") return "VEX"
  return formattedSignalValue(value) ?? "Signal"
}

export function visibleSignalItems<T>(items: readonly T[], maxVisible = 3) {
  const safeMax = Math.max(0, maxVisible)
  return {
    overflowCount: Math.max(0, items.length - safeMax),
    visibleItems: items.slice(0, safeMax),
  }
}
