export function formatLabel(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase())
}

export function optionalText(value: string | null | undefined) {
  return value?.trim() ? value : "N.A."
}
