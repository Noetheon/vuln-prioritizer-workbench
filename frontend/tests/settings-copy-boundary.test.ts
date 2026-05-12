import assert from "node:assert/strict"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const settingsDir = new URL("../src/components/settings", import.meta.url)
const settingsDirPath = fileURLToPath(settingsDir)

function sourceFiles(dir: URL): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = new URL(entry.name, `${dir.href}/`)
    if (entry.isDirectory()) {
      return sourceFiles(path)
    }
    return entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")
      ? [fileURLToPath(path)]
      : []
  })
}

test("settings source stays aligned with local single-user access", () => {
  const forbiddenPhrases = [
    "Account " + "and session",
    "API " + "Tokens",
    "API " + "tokens",
    "Create " + "token",
    "token " + "management",
  ]
  const offenders = sourceFiles(settingsDir).flatMap((path) => {
    if (!statSync(path).isFile()) return []
    const source = readFileSync(path, "utf8")
    return forbiddenPhrases
      .filter((phrase) => source.includes(phrase))
      .map((phrase) => `${relative(join(settingsDirPath, ".."), path)}: ${phrase}`)
  })

  assert.deepEqual(offenders, [])
})
