export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}
