export function shouldClearAuthForApiError(error: unknown) {
  return apiErrorStatus(error) === 401
}

function apiErrorStatus(error: unknown) {
  if (!error || typeof error !== "object" || !("status" in error)) {
    return undefined
  }
  const status = (error as { status: unknown }).status
  return typeof status === "number" ? status : undefined
}
