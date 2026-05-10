import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import test from "node:test"

const findingDetailCssFiles = [
  new URL("../src/styles/finding-detail-decision.css", import.meta.url),
  new URL("../src/styles/finding-detail-evidence.css", import.meta.url),
  new URL("../src/styles/finding-detail-ttp-history.css", import.meta.url),
]
const darkModeCssFile = new URL("../src/styles/dark-mode.css", import.meta.url)

function text(url: URL) {
  return readFileSync(url, "utf8")
}

test("finding detail styles use VPW tokens and scoped table selectors", () => {
  const source = findingDetailCssFiles.map(text).join("\n")
  const tableElementSelectors = source
    .split(/\r?\n/)
    .filter((line) =>
      /(?:^|[\s>,+~])(?:table|thead|tbody|tr|th|td)(?=[\s.#:[>,{])/.test(line),
    )

  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}/)
  assert.doesNotMatch(source, /rgba?\(/)
  assert.doesNotMatch(source, /^\s*\[data-slot/m)
  assert.deepEqual(tableElementSelectors, [])
  assert.match(source, /var\(--vpw-/)
})

test("finding detail styles stay split into focused ownership slices", () => {
  for (const file of findingDetailCssFiles) {
    const lineCount = text(file).split(/\r?\n/).length
    assert.ok(
      lineCount <= 450,
      `${file.pathname} has ${lineCount} lines; split or componentize it`,
    )
  }
  assert.equal(
    existsSync(new URL("../src/styles/finding-detail.css", import.meta.url)),
    false,
  )
})

test("dark mode stays token-driven without a global override sheet", () => {
  assert.equal(existsSync(darkModeCssFile), false)
})
