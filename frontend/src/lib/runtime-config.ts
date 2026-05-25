type RuntimeEnv = {
  MODE?: string
  PROD?: boolean
  VITE_DEMO_MODE?: string
}

declare const __VPW_API_URL__: string | undefined
declare const __VPW_DEMO_MODE__: boolean | undefined

const LOCAL_API_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"])

export function normalizeApiBaseUrl(value: string | undefined): string {
  const trimmed = value?.trim().replace(/\/+$/, "") ?? ""
  if (!trimmed || trimmed === "/") {
    return ""
  }

  try {
    const url = new URL(trimmed)
    if (url.pathname !== "/" || url.search || url.hash) {
      return `${url.origin}${url.pathname === "/" ? "" : url.pathname}`.replace(
        /\/+$/,
        "",
      )
    }
    return url.origin
  } catch {
    return ""
  }
}

export function isLocalApiBaseUrl(value: string | undefined): boolean {
  const normalized = normalizeApiBaseUrl(value)
  if (!normalized) {
    return false
  }
  try {
    return LOCAL_API_HOSTS.has(new URL(normalized).hostname)
  } catch {
    return false
  }
}

export function workbenchApiUrl(path: string | null | undefined): string {
  const normalizedPath = path?.trim()
  if (!normalizedPath) {
    return ""
  }
  const pathWithSlash = normalizedPath.startsWith("/")
    ? normalizedPath
    : `/${normalizedPath}`
  return `${API_BASE_URL}${pathWithSlash}`
}

export function isExplicitDemoModeEnabled(env: RuntimeEnv | undefined) {
  return (
    env?.VITE_DEMO_MODE?.trim().toLowerCase() === "true" &&
    env.PROD !== true &&
    env.MODE !== "production"
  )
}

export const API_BASE_URL =
  typeof __VPW_API_URL__ === "string"
    ? normalizeApiBaseUrl(__VPW_API_URL__)
    : ""

export const DEMO_MODE_ENABLED =
  typeof __VPW_DEMO_MODE__ === "boolean"
    ? __VPW_DEMO_MODE__
    : isExplicitDemoModeEnabled(import.meta.env)
