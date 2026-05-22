type DateFormatOptions = {
  emptyFallback?: string
  formatOptions?: Intl.DateTimeFormatOptions
  invalidFallback?: string | ((value: string) => string)
}

function formatDateValue(
  value: string | null | undefined,
  {
    emptyFallback = "Not recorded",
    formatOptions,
    invalidFallback = emptyFallback,
  }: DateFormatOptions,
) {
  if (!value) {
    return emptyFallback
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return typeof invalidFallback === "function"
      ? invalidFallback(value)
      : invalidFallback
  }
  return new Intl.DateTimeFormat(undefined, formatOptions).format(date)
}

export function formatDateTime(
  value: string | null | undefined,
  options: DateFormatOptions = {},
) {
  return formatDateValue(value, {
    formatOptions: {
      dateStyle: "medium",
      timeStyle: "short",
    },
    ...options,
  })
}

export function formatDate(
  value: string | null | undefined,
  options: DateFormatOptions = {},
) {
  return formatDateValue(value, {
    formatOptions: {
      dateStyle: "medium",
    },
    ...options,
  })
}

export function formatShortDate(
  value: string | null | undefined,
  options: DateFormatOptions = {},
) {
  return formatDateValue(value, {
    formatOptions: {
      day: "2-digit",
      month: "2-digit",
      year: "2-digit",
    },
    ...options,
  })
}
