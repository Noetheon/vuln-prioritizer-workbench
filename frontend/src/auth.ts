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

let authenticatedInCurrentTab = false

export function getAccessToken(): string {
  return ""
}

export function isLoggedIn(): boolean {
  return authenticatedInCurrentTab
}

export function markAuthenticatedSession(): void {
  authenticatedInCurrentTab = true
}

export function setAccessToken(_token?: string): void {
  markAuthenticatedSession()
}

export function clearAccessToken(): void {
  authenticatedInCurrentTab = false
  expireReadableAuthCookies()
}

export function getCsrfToken(cookie = browserCookie()): string {
  const cookieToken = readFirstCookieValue(cookie, csrfCookieNames)
  if (cookieToken) {
    return cookieToken
  }
  return readCsrfMetaToken()
}

export function hasReadableSessionEvidence(): boolean {
  return Boolean(getCsrfToken())
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
