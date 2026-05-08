declare const __VPW_LEGACY_SESSION_TOKEN_STORAGE__: boolean | undefined

const legacySessionTokenStorage =
  typeof __VPW_LEGACY_SESSION_TOKEN_STORAGE__ === "boolean"
    ? __VPW_LEGACY_SESSION_TOKEN_STORAGE__
    : false
const legacySessionTokenKey = "vpw.legacySessionToken"
const csrfCookieNames = [
  "vpw_csrf_token",
  "vpw_csrf",
  "csrf_token",
  "csrftoken",
  "XSRF-TOKEN",
]
const csrfMetaNames = ["csrf-token", "vpw-csrf-token"]
const csrfHeaderName = "X-CSRF-Token"
const unsafeMethods = new Set(["DELETE", "PATCH", "POST", "PUT"])

let inMemoryAccessToken = readLegacySessionToken()
let authenticatedInCurrentTab = false

export function getAccessToken(): string {
  if (!legacySessionTokenStorage) {
    return ""
  }
  if (!inMemoryAccessToken) {
    inMemoryAccessToken = readLegacySessionToken()
  }
  return inMemoryAccessToken
}

export function isLoggedIn(): boolean {
  return authenticatedInCurrentTab || getAccessToken().length > 0
}

export function markAuthenticatedSession(): void {
  authenticatedInCurrentTab = true
}

export function setAccessToken(token?: string): void {
  inMemoryAccessToken = legacySessionTokenStorage ? (token ?? "") : ""
  markAuthenticatedSession()
  writeLegacySessionToken(inMemoryAccessToken)
}

export function clearAccessToken(): void {
  inMemoryAccessToken = ""
  authenticatedInCurrentTab = false
  clearLegacySessionToken()
  expireReadableAuthCookies()
}

export function getCsrfToken(cookie = browserCookie()): string {
  const cookieToken = readFirstCookieValue(cookie, csrfCookieNames)
  if (cookieToken) {
    return cookieToken
  }
  return readCsrfMetaToken()
}

export function csrfHeaderForMethod(method: string): HeadersInit | undefined {
  if (!unsafeMethods.has(method.toUpperCase())) {
    return undefined
  }
  const token = getCsrfToken()
  return token ? { [csrfHeaderName]: token } : undefined
}

export function withCsrfHeader(request: Request): Request {
  if (!unsafeMethods.has(request.method.toUpperCase())) {
    return request
  }
  if (request.headers.has(csrfHeaderName)) {
    return request
  }

  const token = getCsrfToken()
  if (!token) {
    return request
  }

  const headers = new Headers(request.headers)
  headers.set(csrfHeaderName, token)
  return new Request(request, { headers })
}

function browserCookie() {
  return typeof document === "undefined" ? "" : document.cookie
}

function readLegacySessionToken() {
  if (!legacySessionTokenStorage || typeof sessionStorage === "undefined") {
    return ""
  }
  try {
    return sessionStorage.getItem(legacySessionTokenKey) ?? ""
  } catch {
    return ""
  }
}

function writeLegacySessionToken(token: string) {
  if (!legacySessionTokenStorage || typeof sessionStorage === "undefined") {
    return
  }
  try {
    if (token) {
      sessionStorage.setItem(legacySessionTokenKey, token)
    } else {
      sessionStorage.removeItem(legacySessionTokenKey)
    }
  } catch {
    // Session storage can be blocked; cookie sessions remain the primary path.
  }
}

function clearLegacySessionToken() {
  if (!legacySessionTokenStorage || typeof sessionStorage === "undefined") {
    return
  }
  try {
    sessionStorage.removeItem(legacySessionTokenKey)
  } catch {
    // Session storage can be blocked; cookie sessions remain the primary path.
  }
}

function readFirstCookieValue(cookie: string, names: readonly string[]) {
  const pairs = cookie
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)

  for (const name of names) {
    const prefix = `${encodeURIComponent(name)}=`
    const pair = pairs.find((entry) => entry.startsWith(prefix))
    if (!pair) {
      continue
    }
    const value = pair.slice(prefix.length)
    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }
  return ""
}

function readCsrfMetaToken() {
  if (typeof document === "undefined") {
    return ""
  }
  for (const name of csrfMetaNames) {
    const token = document
      .querySelector<HTMLMetaElement>(`meta[name="${name}"]`)
      ?.content.trim()
    if (token) {
      return token
    }
  }
  return ""
}

function expireReadableAuthCookies() {
  if (typeof document === "undefined") {
    return
  }
  for (const name of csrfCookieNames) {
    // biome-ignore lint/suspicious/noDocumentCookie: logout must expire client-readable CSRF cookies on browsers without Cookie Store support.
    document.cookie = `${encodeURIComponent(
      name,
    )}=; Max-Age=0; Path=/; SameSite=Strict`
  }
}
