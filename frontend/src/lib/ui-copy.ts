export function formatLabel(value: string | null | undefined) {
  if (!value) {
    return "Not recorded"
  }
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase())
}

export function optionalText(value: string | null | undefined) {
  return value?.trim() ? value : "Not supplied"
}

export function shortId(value: string | null | undefined) {
  return value ? value.slice(0, 8) : "Not recorded"
}
