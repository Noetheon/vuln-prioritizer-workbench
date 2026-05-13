import { ApiError } from "../../lib/api-client-errors"

export function apiErrorMessage(prefix: string, caught: unknown) {
  if (caught instanceof ApiError) {
    const detail = apiErrorDetail(caught.body)
    return `${prefix}: ${detail ?? caught.message ?? `HTTP ${caught.status}`}`
  }
  return `${prefix}: unexpected client error`
}

function apiErrorDetail(body: unknown) {
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
    return typeof record.message === "string" && record.message.trim()
      ? record.message
      : null
  }
  return null
}
