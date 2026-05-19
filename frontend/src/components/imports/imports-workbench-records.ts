export function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

export function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}
