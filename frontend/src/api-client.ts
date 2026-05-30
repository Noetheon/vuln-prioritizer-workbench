import { client } from "./client/client.gen"
import { createApiFetch, ApiError } from "./lib/api-client-errors"

export * from "./client"
export type { RunParseErrorV2 as ImportParseErrorPublic } from "./client"
export { client } from "./client/client.gen"
export { ApiError, createApiFetch } from "./lib/api-client-errors"
export type FindingsReadProjectFindingsData = Parameters<
  typeof import("./client").FindingsService.readProjectFindings
>[0]

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
  const nextConfig: Parameters<typeof client.setConfig>[0] = {
    credentials: "include" as const,
    responseStyle: "data" as const,
    throwOnError: true as const,
    ...config,
  }
  client.setConfig({
    ...nextConfig,
    fetch: createApiFetch(nextConfig.fetch),
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
