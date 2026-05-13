export class ApiError extends Error {
  body: unknown
  status: number

  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `HTTP ${status}`)
    this.name = "ApiError"
    this.status = status
    this.body = body
  }
}

const NETWORK_ERROR_DETAIL =
  "The Workbench API request did not receive a response. Check that the backend is running and that same-origin or CORS settings allow this browser session."
const NETWORK_ERROR_MESSAGE = "Workbench API request failed"

export function createApiFetch(fetcher: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    try {
      return await fetcher(input, init)
    } catch (caught) {
      if (caught instanceof ApiError || isAbortError(caught)) {
        throw caught
      }
      throw new ApiError(0, { detail: NETWORK_ERROR_DETAIL }, NETWORK_ERROR_MESSAGE)
    }
  }
}

function isAbortError(caught: unknown) {
  return (
    typeof caught === "object" &&
    caught !== null &&
    "name" in caught &&
    (caught as { name?: unknown }).name === "AbortError"
  )
}
