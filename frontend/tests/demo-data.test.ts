import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { join, relative } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const frontendRoot = fileURLToPath(new URL("..", import.meta.url))
const srcRoot = join(frontendRoot, "src")

type SourceFile = {
  path: string
  relativePath: string
}

function sourceFiles(dir: string): SourceFile[] {
  if (!existsSync(dir)) return []

  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    const relativePath = relative(frontendRoot, path)

    if (entry.isDirectory()) {
      if (relativePath === "src/client") return []
      return sourceFiles(path)
    }

    if (!/\.(?:ts|tsx)$/.test(entry.name)) return []
    if (entry.name.endsWith(".gen.ts")) return []

    return [{ path, relativePath }]
  })
}

test("frontend has no static demo data layer", () => {
  const libRoot = join(srcRoot, "lib")
  const demoDataFiles = readdirSync(libRoot).filter((name) =>
    /^demo-data(?:-[a-z-]+)?\.ts$/.test(name),
  )

  assert.deepEqual(demoDataFiles, [])
})

test("frontend runtime has no frontend-only demo mode flag", () => {
  const checkedFiles = [
    ...sourceFiles(srcRoot),
    {
      path: join(frontendRoot, "vite.config.ts"),
      relativePath: "vite.config.ts",
    },
  ]
  const forbidden = ["DEMO_MODE_ENABLED", "VITE_DEMO_MODE", "__VPW_DEMO_MODE__"]
  const offenders = checkedFiles.flatMap(({ path, relativePath }) => {
    const source = readFileSync(path, "utf8")

    return forbidden
      .filter((token) => source.includes(token))
      .map((token) => `${relativePath}: ${token}`)
  })

  assert.deepEqual(offenders, [])
})

test("frontend source does not import removed demo data modules", () => {
  const offenders = sourceFiles(srcRoot).flatMap(({ path, relativePath }) => {
    const source = readFileSync(path, "utf8")

    return source.includes("demo-data")
      ? [`${relativePath}: demo-data import/reference`]
      : []
  })

  assert.deepEqual(offenders, [])
})
