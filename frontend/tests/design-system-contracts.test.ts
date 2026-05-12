import assert from "node:assert/strict"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join, relative, sep } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const frontendRoot = fileURLToPath(new URL("../", import.meta.url))
const srcRoot = fileURLToPath(new URL("../src/", import.meta.url))

const sourceExtensions = new Set([".css", ".ts", ".tsx"])
const ignoredPathParts = new Set([
  "client",
  "vite-env.d.ts",
])

const colorTokenFiles = new Set([
  "src/lib/vpw-tokens.json",
  "src/lib/vpw-tokens.ts",
  "src/styles/tokens.css",
])

const showcaseFiles = new Set([
  "src/components/vpw/VpwDesignSystemShowcase.tsx",
])

const rawControlAllowlist = new Set([
  "src/components/ui/button.tsx",
  "src/components/ui/input.tsx",
  "src/components/ui/table.tsx",
  "src/components/vpw/VpwFileInput.tsx",
])

const rawTableAllowlist = new Set([
  "src/components/ui/table.tsx",
  "src/components/vpw/VpwDataTable.tsx",
  "src/components/dashboard/DashboardSignalOverview.tsx",
])

const retiredStyleFiles = [
  "src/styles/shadcn-compat.css",
  "src/styles/dark-mode.css",
  "src/styles/finding-detail.css",
]

const rawColorPattern = /#[0-9a-fA-F]{3,8}|rgba?\(/g
const rawPalettePattern =
  /\b(?:bg|text|border)-(?:slate|gray|zinc|neutral|stone|amber|yellow|orange|red|green|emerald|blue|sky|indigo|purple|violet|pink)-\d{2,3}(?:\/\d+)?\b/g
const spacingPattern = /\bspace-[xy]-\d(?:\.\d)?\b/g
const featureDarkColorPattern =
  /\bdark:(?:bg|text|border)-(?:slate|gray|zinc|neutral|stone|amber|yellow|orange|red|green|emerald|blue|sky|indigo|purple|violet|pink)-\d{2,3}(?:\/\d+)?\b/g
const hardPanelRadiusPattern =
  /border-radius:\s*(?:9|10|11|1[2-9]|[2-9][0-9])px\b/g
const oversizedRadiusTokenPattern =
  /--(?:vpw-)?radius-(?:lg|xl):\s*(?:9|10|11|1[2-9]|[2-9][0-9])px\b/g
const tableDescendantUtilityPattern =
  /\[&[^\]]*(?:table|thead|tbody|tr|th|td)[^\]]*\]/g
const trackingUtilityPattern =
  /\btracking-(?:tighter|tight|normal|wide|wider|widest|\[[^\]]+\])\b/g
const letterSpacingPattern = /letter-spacing:\s*([^;]+);/g
const viewportFontSizePattern =
  /font-size:\s*clamp\([^;]*(?:vw|vh|vmin|vmax)[^;]*\);/g

function readProjectFile(path: string) {
  return readFileSync(join(frontendRoot, path), "utf8")
}

function walk(directory: string, files: string[] = []) {
  for (const item of readdirSync(directory)) {
    const absolute = join(directory, item)
    const stats = statSync(absolute)
    if (stats.isDirectory()) {
      walk(absolute, files)
      continue
    }
    if (!sourceExtensions.has(extname(item))) continue

    const projectPath = relative(frontendRoot, absolute).split(sep).join("/")
    if ([...ignoredPathParts].some((part) => projectPath.includes(part)))
      continue
    files.push(projectPath)
  }
  return files.sort()
}

function violationsFor(pattern: RegExp, source: string) {
  return [...source.matchAll(pattern)].map((match) => match[0])
}

test("design-system colors are tokenized outside token and showcase files", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    if (colorTokenFiles.has(path) || showcaseFiles.has(path)) continue
    const source = readProjectFile(path)
    const rawColors = violationsFor(rawColorPattern, source)
    const rawPalettes = violationsFor(rawPalettePattern, source)
    if (rawColors.length > 0 || rawPalettes.length > 0) {
      offenders.push(`${path}: ${[...rawColors, ...rawPalettes].join(", ")}`)
    }
  }

  assert.deepEqual(offenders, [])
})

test("feature code uses gap utilities instead of space-x/space-y", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    if (showcaseFiles.has(path)) continue
    const source = readProjectFile(path)
    const matches = violationsFor(spacingPattern, source)
    if (matches.length > 0) offenders.push(`${path}: ${matches.join(", ")}`)
  }

  assert.deepEqual(offenders, [])
})

test("dark mode is token driven outside global token files", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    if (path === "src/styles/tokens.css") continue
    const source = readProjectFile(path)
    const matches = violationsFor(featureDarkColorPattern, source)
    if (matches.length > 0) offenders.push(`${path}: ${matches.join(", ")}`)
  }

  assert.deepEqual(offenders, [])
})

test("raw controls and tables are isolated to UI adapters", () => {
  const rawControlOffenders: string[] = []
  const rawTableOffenders: string[] = []

  for (const path of walk(srcRoot)) {
    const source = readProjectFile(path)

    if (!rawControlAllowlist.has(path)) {
      const controls = violationsFor(/<(?:button|input)\b/g, source)
      if (controls.length > 0) {
        rawControlOffenders.push(`${path}: ${controls.join(", ")}`)
      }
    }

    if (!rawTableAllowlist.has(path)) {
      const tables = violationsFor(/<table\b/g, source)
      if (tables.length > 0)
        rawTableOffenders.push(`${path}: ${tables.join(", ")}`)
    }
  }

  assert.deepEqual(rawControlOffenders, [])
  assert.deepEqual(rawTableOffenders, [])
})

test("domain styles do not target shadcn internals or global elements", () => {
  const domainCssFiles = [
    "src/styles/dashboard.css",
    "src/styles/findings.css",
    "src/styles/finding-detail-decision.css",
    "src/styles/finding-detail-evidence.css",
    "src/styles/finding-detail-ttp-history.css",
  ]
  const forbiddenPattern =
    /(?:^\s*(?:(?:table|thead|tbody|tr|th|td|input|select|textarea|button)\b|\[data-slot|[^\n{]*\[role=|[^\n{]*:nth-child)|(?:^|[\s>,+~])(?:table|thead|tbody|tr|th|td)(?=[\s.#:[>,{]))/m
  const offenders = domainCssFiles.filter((path) =>
    forbiddenPattern.test(readProjectFile(path)),
  )

  assert.deepEqual(offenders, [])
})

test("feature code does not reach into table descendants", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    if (rawTableAllowlist.has(path) || showcaseFiles.has(path)) continue
    const source = readProjectFile(path)
    const matches = violationsFor(tableDescendantUtilityPattern, source)
    if (matches.length > 0) offenders.push(`${path}: ${matches.join(", ")}`)
  }

  assert.deepEqual(offenders, [])
})

test("tables expose a single keyboard-scroll owner", () => {
  const tablePrimitive = readProjectFile("src/components/ui/table.tsx")
  assert.doesNotMatch(
    tablePrimitive,
    /data-slot="table-container"[\s\S]{0,220}tabIndex=\{0\}/,
  )
  assert.match(
    readProjectFile("src/components/vpw/VpwDataTable.tsx"),
    /tabIndex=\{0\}/,
  )
})

test("app shell owns page scrolling in the content region", () => {
  const appShell = readProjectFile("src/components/app/AppShell.tsx")
  const baseCss = readProjectFile("src/styles/base.css")

  assert.match(appShell, /vpw-app-shell/)
  assert.match(appShell, /<main className="[^"]*overflow-hidden/)
  assert.match(
    appShell,
    /aria-label="Workbench page content"[\s\S]{0,180}className="[^"]*overflow-y-auto/,
  )
  assert.match(
    appShell,
    /aria-label="Workbench page content"[\s\S]{0,220}tabIndex=\{0\}/,
  )
  assert.doesNotMatch(appShell, /sticky top-0/)
  assert.match(baseCss, /html:has\(\.vpw-app-shell\)/)
  assert.match(baseCss, /body:has\(\.vpw-app-shell\)/)
})

test("stylesheets do not couple to shadcn data-slot internals", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    if (!path.endsWith(".css")) continue
    const source = readProjectFile(path)
    const matches = violationsFor(/\[data-slot/g, source)
    if (matches.length > 0) offenders.push(`${path}: ${matches.join(", ")}`)
  }

  assert.deepEqual(offenders, [])
})

test("retired compatibility and dark-mode override styles stay retired", () => {
  const indexCss = readProjectFile("src/index.css")
  const offenders = retiredStyleFiles.filter(
    (path) => existsSync(join(frontendRoot, path)) || indexCss.includes(path),
  )

  assert.deepEqual(offenders, [])
})

test("runtime CSS, TypeScript tokens, JSON tokens, and showcase copy stay synchronized", () => {
  const tokenJson = JSON.parse(readProjectFile("src/lib/vpw-tokens.json")) as {
    layout: { maxWidth: string }
    radius: Record<string, string>
  }
  const tokenTs = readProjectFile("src/lib/vpw-tokens.ts")
  const tokenCss = readProjectFile("src/styles/tokens.css")
  const showcase = readProjectFile("src/components/vpw/VpwDesignSystemShowcase.tsx")
  const expectedRadius = {
    sm: "4px",
    md: "6px",
    lg: "8px",
    xl: "8px",
    pill: "9999px",
  }

  assert.equal(tokenJson.layout.maxWidth, "1920px")
  assert.deepEqual(tokenJson.radius, expectedRadius)
  assert.match(tokenTs, /maxWidth:\s*"1920px"/)
  assert.match(tokenCss, /--vpw-container-max:\s*1920px;/)
  assert.match(showcase, /1920px max/)

  for (const [name, value] of Object.entries(expectedRadius)) {
    assert.match(tokenTs, new RegExp(`${name}:\\s*"${value}"`))
    assert.match(tokenCss, new RegExp(`--vpw-radius-${name}:\\s*${value};`))
  }

  assert.match(showcase, /4 \/ 6 \/ 8 \/ 8/)
})

test("cards and panels stay inside the eight-pixel radius system", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    const source = readProjectFile(path)
    const hardPanelRadii = violationsFor(hardPanelRadiusPattern, source)
    const oversizedTokens = violationsFor(oversizedRadiusTokenPattern, source)
    if (hardPanelRadii.length > 0 || oversizedTokens.length > 0) {
      offenders.push(
        `${path}: ${[...hardPanelRadii, ...oversizedTokens].join(", ")}`,
      )
    }
  }

  assert.deepEqual(offenders, [])
})

test("typography does not use viewport-scaled text or tracking drift", () => {
  const offenders: string[] = []

  for (const path of walk(srcRoot)) {
    const source = readProjectFile(path)
    const trackingUtilities = violationsFor(trackingUtilityPattern, source)
    const nonzeroLetterSpacing = [...source.matchAll(letterSpacingPattern)]
      .filter((match) => match[1]?.trim() !== "0")
      .map((match) => match[0])
    const viewportFontSizes = violationsFor(viewportFontSizePattern, source)
    if (
      trackingUtilities.length > 0 ||
      nonzeroLetterSpacing.length > 0 ||
      viewportFontSizes.length > 0
    ) {
      offenders.push(
        `${path}: ${[
          ...trackingUtilities,
          ...nonzeroLetterSpacing,
          ...viewportFontSizes,
        ].join(", ")}`,
      )
    }
  }

  assert.deepEqual(offenders, [])
})
