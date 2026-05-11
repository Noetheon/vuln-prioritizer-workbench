import type {
  AssetCriticality,
  AssetEnvironment,
  AssetExposure,
  AssetPublic,
} from "../../api-client"
import type { VpwBadgeTone } from "../vpw"

export function criticalityTone(
  value: AssetCriticality | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

export function exposureTone(
  value: AssetExposure | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "internet-facing":
      return "warning"
    case "internal":
      return "info"
    case "private":
      return "success"
    default:
      return "neutral"
  }
}

export function environmentTone(
  value: AssetEnvironment | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "production":
      return "warning"
    case "staging":
    case "test":
      return "info"
    case "development":
      return "support"
    default:
      return "neutral"
  }
}

export function findingPriorityTone(
  value: string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

export function findingStatusTone(value: string | null | undefined): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "resolved":
    case "accepted":
    case "false_positive":
      return "success"
    case "in_progress":
    case "triaged":
      return "info"
    case "deferred":
      return "warning"
    default:
      return "neutral"
  }
}

export function assetScoreTone(asset: AssetPublic): VpwBadgeTone {
  return asset.rescore_needed ? "warning" : "success"
}

export function scoreStatusLabel(asset: AssetPublic) {
  return asset.rescore_needed ? "Re-score needed" : "Current"
}
