type HeaderValue =
  | HeadersInit
  | Record<string, string | number | boolean | string[] | number[] | boolean[] | null | undefined | unknown>
  | undefined
type HttpMethod = "delete" | "get" | "head" | "options" | "patch" | "post" | "put"
type ParseAs = "arrayBuffer" | "auto" | "blob" | "formData" | "json" | "stream" | "text"
type ResponseStyle = "data" | "fields"

type BodySerializer = (body: unknown) => BodyInit | undefined
type DataOf<TData> = TData extends Record<string, unknown> ? TData[keyof TData] : TData

export interface TDataShape {
  body?: unknown
  headers?: unknown
  path?: unknown
  query?: unknown
  url: string
}

export interface ClientOptions {
  baseUrl?: string
  responseStyle?: ResponseStyle
  throwOnError?: boolean
}

export type Config<_TOptions extends ClientOptions = ClientOptions> = Omit<
  RequestInit,
  "body" | "headers" | "method"
> & {
  baseUrl?: string
  bodySerializer?: BodySerializer | null
  fetch?: typeof fetch
  headers?: HeaderValue
  method?: Uppercase<HttpMethod>
  parseAs?: ParseAs
  responseStyle?: ResponseStyle
  throwOnError?: boolean
}

export type RequestOptions<
  _TData = unknown,
  TResponseStyle extends ResponseStyle = "fields",
  ThrowOnError extends boolean = boolean,
  Url extends string = string,
> = Config<{
  responseStyle: TResponseStyle
  throwOnError: ThrowOnError
}> & {
  body?: unknown
  path?: Record<string, unknown>
  query?: Record<string, unknown>
  url: Url
}

export type RequestResult<
  TData = unknown,
  TError = unknown,
  ThrowOnError extends boolean = boolean,
  TResponseStyle extends ResponseStyle = "fields",
> = ThrowOnError extends true
  ? Promise<
      TResponseStyle extends "data"
        ? DataOf<TData>
        : {
            data: DataOf<TData>
            request: Request
            response: Response
          }
    >
  : Promise<
      TResponseStyle extends "data"
        ? DataOf<TData> | undefined
        :
            | {
                data: DataOf<TData>
                error: undefined
                request?: Request
                response?: Response
              }
            | {
                data: undefined
                error: DataOf<TError>
                request?: Request
                response?: Response
              }
    >

export type Options<
  TData extends TDataShape = TDataShape,
  ThrowOnError extends boolean = boolean,
  TResponse = unknown,
  TResponseStyle extends ResponseStyle = "fields",
> = Omit<RequestOptions<TResponse, TResponseStyle, ThrowOnError>, "body" | "path" | "query" | "url"> &
  ([TData] extends [never] ? unknown : Omit<TData, "url">)

type ClientParamSource = Record<string, unknown> | undefined

type ClientParamArg = {
  in?: "path" | "query"
  key: string
  map?: "body"
}

type ClientParamConfig = {
  args?: ClientParamArg[]
}

type ClientMethod = <
  TData = unknown,
  TError = unknown,
  ThrowOnError extends boolean = boolean,
  TResponseStyle extends ResponseStyle = "fields",
>(
  options: Omit<RequestOptions<TData, TResponseStyle, ThrowOnError>, "method">,
) => RequestResult<TData, TError, ThrowOnError, TResponseStyle>

type RequestMethod = <
  TData = unknown,
  TError = unknown,
  ThrowOnError extends boolean = boolean,
  TResponseStyle extends ResponseStyle = "fields",
>(
  options: Omit<RequestOptions<TData, TResponseStyle, ThrowOnError>, "method"> &
    Pick<Required<RequestOptions<TData, TResponseStyle, ThrowOnError>>, "method">,
) => RequestResult<TData, TError, ThrowOnError, TResponseStyle>

type ErrorInterceptor = (error: unknown, response?: Response) => unknown

export type Client = Record<HttpMethod, ClientMethod> & {
  buildUrl: (options: { path?: Record<string, unknown>; query?: Record<string, unknown>; url: string } & Config) => string
  getConfig: () => Config<Required<ClientOptions>>
  interceptors: {
    error: {
      use: (interceptor: ErrorInterceptor) => () => void
    }
  }
  request: RequestMethod
  setConfig: (config: Config) => Config<Required<ClientOptions>>
}

export const formDataBodySerializer = {
  bodySerializer(body: unknown) {
    if (body instanceof FormData) {
      return body
    }

    const formData = new FormData()
    if (!body || typeof body !== "object") {
      return formData
    }

    for (const [key, value] of Object.entries(body)) {
      appendFormValue(formData, key, value)
    }
    return formData
  },
}

export function createConfig<TOptions extends ClientOptions = ClientOptions>(
  override: Config<TOptions> = {},
) {
  return {
    baseUrl: "",
    credentials: "same-origin" as RequestCredentials,
    responseStyle: "fields" as ResponseStyle,
    throwOnError: false,
    ...override,
  } as Config<Required<ClientOptions> & TOptions>
}

export function createClient(initialConfig: Config = createConfig()): Client {
  let config = createConfig(initialConfig)
  const errorInterceptors = new Set<ErrorInterceptor>()

  const request = ((options) =>
    sendRequest({ ...config, ...options }, errorInterceptors)) as RequestMethod

  const client: Client = {
    buildUrl(options) {
      return buildUrl({ ...config, ...options })
    },
    delete(options) {
      return request({ ...options, method: "DELETE" })
    },
    get(options) {
      return request({ ...options, method: "GET" })
    },
    getConfig() {
      return config
    },
    head(options) {
      return request({ ...options, method: "HEAD" })
    },
    interceptors: {
      error: {
        use(interceptor) {
          errorInterceptors.add(interceptor)
          return () => {
            errorInterceptors.delete(interceptor)
          }
        },
      },
    },
    options(options) {
      return request({ ...options, method: "OPTIONS" })
    },
    patch(options) {
      return request({ ...options, method: "PATCH" })
    },
    post(options) {
      return request({ ...options, method: "POST" })
    },
    put(options) {
      return request({ ...options, method: "PUT" })
    },
    request,
    setConfig(nextConfig) {
      config = createConfig({ ...config, ...nextConfig })
      return config
    },
  }

  return client
}

export function buildClientParams(
  sources: ClientParamSource[],
  configs: ClientParamConfig[],
) {
  const params: {
    body?: unknown
    headers: Record<string, unknown>
    path: Record<string, unknown>
    query: Record<string, unknown>
  } = {
    headers: {},
    path: {},
    query: {},
  }

  const source = sources.find(Boolean) ?? {}
  for (const config of configs) {
    for (const arg of config.args ?? []) {
      const value = source[arg.key]
      if (value === undefined) {
        continue
      }

      if (arg.map === "body") {
        params.body = value
      } else if (arg.in === "path") {
        params.path[arg.key] = value
      } else if (arg.in === "query") {
        params.query[arg.key] = value
      }
    }
  }

  return params
}

async function sendRequest(
  options: RequestOptions,
  errorInterceptors: Set<ErrorInterceptor>,
): Promise<unknown> {
  const url = buildUrl(options)
  const headers = buildHeaders(options.headers)
  const body = serializeBody(options.body, options.bodySerializer, headers)
  const request = new Request(url, {
    ...options,
    body,
    headers,
    method: options.method ?? "GET",
  })
  const fetcher = options.fetch ?? fetch
  const response = await fetcher(request)
  const payload = await parseResponse(response, options.parseAs)
  const responseStyle = options.responseStyle ?? "fields"

  if (!response.ok) {
    let error: unknown = payload
    for (const interceptor of errorInterceptors) {
      error = interceptor(error, response)
    }

    if (options.throwOnError) {
      throw error
    }

    if (responseStyle === "data") {
      return undefined
    }

    return {
      data: undefined,
      error,
      request,
      response,
    }
  }

  if (responseStyle === "data") {
    return payload
  }

  return {
    data: payload,
    request,
    response,
  }
}

function buildUrl(options: { baseUrl?: string; path?: Record<string, unknown>; query?: Record<string, unknown>; url: string }) {
  const baseUrl = options.baseUrl ?? ""
  const rawPath = applyPathParams(options.url, options.path)
  const href = `${baseUrl}${rawPath}`
  const query = buildQuery(options.query)

  if (!query) {
    return href
  }
  return `${href}${href.includes("?") ? "&" : "?"}${query}`
}

function applyPathParams(url: string, pathParams: Record<string, unknown> = {}) {
  return url.replace(/\{([^}]+)\}/g, (_match, key: string) => {
    const value = pathParams[key]
    if (value === undefined || value === null) {
      return ""
    }
    return encodeURIComponent(String(value))
  })
}

function buildQuery(queryParams: Record<string, unknown> = {}) {
  const search = new URLSearchParams()

  for (const [key, value] of Object.entries(queryParams)) {
    appendQueryValue(search, key, value)
  }

  return search.toString()
}

function appendQueryValue(search: URLSearchParams, key: string, value: unknown) {
  if (value === undefined || value === null) {
    return
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      appendQueryValue(search, key, item)
    }
    return
  }

  search.append(key, value instanceof Date ? value.toISOString() : String(value))
}

function buildHeaders(headers: HeaderValue) {
  const result = new Headers()
  if (!headers) {
    return result
  }

  const source = new Headers(headers as HeadersInit)
  for (const [key, value] of source.entries()) {
    if (value === "null") {
      continue
    }
    result.set(key, value)
  }

  return result
}

function serializeBody(
  body: unknown,
  bodySerializer: BodySerializer | null | undefined,
  headers: Headers,
) {
  if (body === undefined || body === null) {
    return undefined
  }

  if (bodySerializer) {
    return bodySerializer(body)
  }

  if (isBodyInit(body)) {
    return body
  }

  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  return JSON.stringify(body)
}

function isBodyInit(body: unknown): body is BodyInit {
  return (
    typeof body === "string" ||
    body instanceof Blob ||
    body instanceof ArrayBuffer ||
    body instanceof FormData ||
    body instanceof URLSearchParams ||
    ArrayBuffer.isView(body)
  )
}

async function parseResponse(response: Response, parseAs: ParseAs = "auto") {
  if (response.status === 204) {
    return undefined
  }

  const parser = parseAs === "auto" ? inferParser(response) : parseAs
  if (parser === "arrayBuffer") {
    return response.arrayBuffer()
  }
  if (parser === "blob") {
    return response.blob()
  }
  if (parser === "formData") {
    return response.formData()
  }
  if (parser === "stream") {
    return response.body
  }
  if (parser === "text") {
    return response.text()
  }

  const text = await response.text()
  if (!text) {
    return undefined
  }

  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function inferParser(response: Response): Exclude<ParseAs, "auto"> {
  const contentType = response.headers.get("Content-Type") ?? ""
  if (contentType.includes("application/json") || contentType.includes("+json")) {
    return "json"
  }
  return "text"
}

function appendFormValue(formData: FormData, key: string, value: unknown) {
  if (value === undefined || value === null) {
    return
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      appendFormValue(formData, key, item)
    }
    return
  }

  if (value instanceof Blob) {
    formData.append(key, value)
    return
  }

  if (typeof value === "object") {
    formData.append(key, JSON.stringify(value))
    return
  }

  formData.append(key, String(value))
}
