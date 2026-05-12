export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "Not recorded"
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "Not recorded"
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}
