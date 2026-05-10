import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"

const findingDetailCssFile = new URL(
  "../src/styles/finding-detail.css",
  import.meta.url,
)
const darkModeCssFile = new URL("../src/styles/dark-mode.css", import.meta.url)

function text(url: URL) {
  return readFileSync(url, "utf8")
}

test("finding detail styles use VPW tokens and scoped table selectors", () => {
  const source = text(findingDetailCssFile)

  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}/)
  assert.doesNotMatch(source, /rgba?\(/)
  assert.doesNotMatch(source, /^table\s*\{/m)
  assert.doesNotMatch(source, /^th\s*\{/m)
  assert.doesNotMatch(source, /^td\s*\{/m)
  assert.match(source, /\.finding-decision-workflow table\s*\{/)
  assert.match(source, /var\(--vpw-/)
})

test("dark mode overrides are backed by semantic VPW tokens", () => {
  const source = text(darkModeCssFile)

  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}/)
  assert.match(source, /@media \(prefers-color-scheme: dark\)/)
  assert.match(source, /var\(--vpw-bg-app\)/)
  assert.match(source, /var\(--vpw-text-primary\)/)
})
