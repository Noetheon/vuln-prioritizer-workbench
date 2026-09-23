import { ApiError } from "./api-client-errors.ts"

export function decisionRefreshPollingInterval(caught: unknown): 2000 | false {
  if (!(caught instanceof ApiError) || caught.status !== 503) return false
  const body = caught.body as { detail?: { code?: unknown } } | null
  return body?.detail?.code === "decision_refresh_pending" ? 2000 : false
}

export function millisecondsUntilUtcDayChange(now: Date): number {
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1) - now.getTime() + 100
}
