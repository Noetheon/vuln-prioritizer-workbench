import assert from "node:assert/strict"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { dirname, join } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const frontendRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const sourceRoot = join(frontendRoot, "src")
const clientRoot = join(sourceRoot, "client")

function sourceFiles(directory: string): string[] {
  return readdirSync(directory)
    .flatMap((entry) => {
      const path = join(directory, entry)
      if (path.startsWith(clientRoot)) {
        return []
      }
      if (statSync(path).isDirectory()) {
        return sourceFiles(path)
      }
      return path.endsWith(".ts") || path.endsWith(".tsx") ? [path] : []
    })
    .sort()
}

test("active frontend copy does not expose N.A. fallbacks", () => {
  const offenders = sourceFiles(sourceRoot).filter((path) =>
    readFileSync(path, "utf8").includes("N.A."),
  )

  assert.deepEqual(offenders, [])
})
