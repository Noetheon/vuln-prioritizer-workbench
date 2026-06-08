import { readFileSync } from "node:fs"
import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, loadEnv } from "vite"

const packageJson = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf-8"),
) as { version?: string }

function normalizedApiUrl(value: string | undefined) {
  const trimmed = value?.trim().replace(/\/+$/, "") ?? ""
  if (!trimmed || trimmed === "/") {
    return ""
  }
  try {
    const url = new URL(trimmed)
    return url.origin
  } catch {
    return ""
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "")
  const isProductionBuild =
    mode === "production" || process.env.NODE_ENV === "production"
  const configuredApiUrl = normalizedApiUrl(env.VITE_API_URL)
  const devProxyTarget =
    normalizedApiUrl(env.VITE_DEV_PROXY_TARGET) || "http://127.0.0.1:8000"
  const bundledApiUrl = isProductionBuild ? "" : configuredApiUrl

  return {
    define: {
      __VPW_API_URL__: JSON.stringify(bundledApiUrl),
      __VPW_FRONTEND_VERSION__: JSON.stringify(packageJson.version ?? "0.0.0"),
    },
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
    server: {
      host: "127.0.0.1",
      port: 5173,
      proxy: {
        "/api": devProxyTarget,
      },
    },
    plugins: [tailwindcss(), react()],
  }
})
