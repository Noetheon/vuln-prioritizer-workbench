import { client } from "./client/client.gen"

export * from "./client"
export { client } from "./client/client.gen"
export type FindingsReadProjectFindingsData = Parameters<
  typeof import("./client").FindingsService.readProjectFindings
>[0]

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
}
