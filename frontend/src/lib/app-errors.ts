import type { ImportParseErrorPublic } from "../api-client"
import { ApiError } from "./api-client-errors"

export function apiErrorMessage(prefix: string, caught: unknown) {
  if (caught instanceof ApiError) {
    const detail = apiErrorDetail(caught.body)
    return `${prefix}: ${detail ?? caught.message ?? `HTTP ${caught.status}`}`
  }
  return `${prefix}: unexpected client error`
}

export function apiErrorDetail(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  if (typeof detail === "string" && detail.trim()) {
    return detail
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) =>
        typeof item === "object" && item !== null && "msg" in item
          ? String((item as { msg?: unknown }).msg)
          : "",
      )
      .filter(Boolean)
    return messages.length > 0 ? messages.join("; ") : "validation failed"
  }
  if (typeof detail === "object" && detail !== null) {
    const record = detail as Record<string, unknown>
    const assetContextError = objectRecord(record.asset_context_error)
    const analysisError = objectRecord(record.analysis_error)
    const vexError = objectRecord(record.vex_error)
    const vexErrorMessage = stringValue(vexError.message)
    if (vexErrorMessage) {
      const detailMessage = stringValue(record.message)
      return detailMessage
        ? `${detailMessage} ${vexErrorMessage}`
        : vexErrorMessage
    }
    return (
      stringValue(record.message) ??
      stringValue(assetContextError.message) ??
      stringValue(analysisError.message) ??
      stringValue(record.error) ??
      null
    )
  }
  return null
}

export function analysisRunIdFromError(caught: unknown) {
  if (!(caught instanceof ApiError)) {
    return null
  }
  const detail = errorDetailObject(caught.body)
  const analysisRunId = detail?.analysis_run_id
  return typeof analysisRunId === "string" ? analysisRunId : null
}

export function parseErrorsFromError(caught: unknown) {
  if (!(caught instanceof ApiError)) {
    return []
  }
  const detail = errorDetailObject(caught.body)
  const parseErrors = detail?.parse_errors
  return Array.isArray(parseErrors)
    ? parseErrors.filter(isImportParseError)
    : []
}

function errorDetailObject(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  return typeof detail === "object" && detail !== null
    ? (detail as Record<string, unknown>)
    : null
}

function isImportParseError(value: unknown): value is ImportParseErrorPublic {
  return (
    typeof value === "object" &&
    value !== null &&
    "message" in value &&
    typeof (value as { message?: unknown }).message === "string"
  )
}

export function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

export function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}

export function arrayRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is Record<string, unknown> =>
          typeof entry === "object" && entry !== null,
      )
    : []
}

export function joinedValues(values: Array<string | null | undefined>) {
  const present = values.filter(
    (value): value is string =>
      typeof value === "string" && value.trim() !== "",
  )
  return present.length > 0 ? present.join(" / ") : "Not supplied"
}
