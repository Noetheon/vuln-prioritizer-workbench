import { client } from "./client/client.gen"
import { withCsrfHeader } from "./auth"

export * from "./client"
export { client } from "./client/client.gen"
export type FindingsReadProjectFindingsData = Parameters<
  typeof import("./client").FindingsService.readProjectFindings
>[0]

type TokenProvider =
  | string
  | undefined
  | (() => Promise<string | undefined> | string | undefined)

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

let hasErrorInterceptor = false
let hasRequestInterceptor = false

function installRequestInterceptor() {
  if (hasRequestInterceptor) {
    return
  }

  client.interceptors.request.use((request) => withCsrfHeader(request))
  hasRequestInterceptor = true
}

function installErrorInterceptor() {
  if (hasErrorInterceptor) {
    return
  }

  client.interceptors.error.use((error, response) => {
    if (error instanceof ApiError) {
      return error
    }
    const status = response?.status ?? 0
    const statusText = response?.statusText
    const message = statusText ? `HTTP ${status}: ${statusText}` : `HTTP ${status}`
    return new ApiError(status, error, message)
  })
  hasErrorInterceptor = true
}

function configureClient(config: Parameters<typeof client.setConfig>[0]) {
  installRequestInterceptor()
  installErrorInterceptor()
  client.setConfig({
    credentials: "include",
    responseStyle: "data",
    throwOnError: true,
    ...config,
  })
}

export const OpenAPI = {
  get BASE() {
    return client.getConfig().baseUrl ?? ""
  },
  set BASE(baseUrl: string) {
    configureClient({ baseUrl })
  },
  set TOKEN(provider: TokenProvider) {
    configureClient({
      auth: async () => {
        if (typeof provider === "function") {
          return provider()
        }
        return provider
      },
    })
  },
}
