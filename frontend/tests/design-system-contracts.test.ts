import assert from "node:assert/strict"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join, relative, sep } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

import {
  formatRiskScore,
  normalizeRiskLevel,
  normalizeSignalKind,
  normalizeStatus,
  riskLabel,
  riskScoreTone,
  riskTone,
  signalLabel,
  signalTone,
  statusLabel,
  statusTone,
  visibleSignalItems,
} from "../src/components/vpw/semantic-badge-model.ts"

const frontendRoot = fileURLToPath(new URL("../", import.meta.url))
const srcRoot = fileURLToPath(new URL("../src/", import.meta.url))

const sourceExtensions = new Set([".css", ".ts", ".tsx"])
const ignoredPathParts = new Set(["client", "vite-env.d.ts"])

const colorTokenFiles = new Set([
  "src/lib/vpw-tokens.json",
  "src/lib/vpw-tokens.ts",
  "src/styles/tokens.css",
])

const showcaseFiles = new Set([
  "src/components/vpw/VpwDesignSystemShowcase.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseData.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseControls.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseEvidence.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseFrame.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseFoundations.tsx",
  "src/components/vpw/VpwDesignSystemShowcaseStates.tsx",
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

const rowActionContractFiles = [
  "src/components/assets/AssetTableColumns.tsx",
  "src/components/dashboard/DashboardRemediationColumns.tsx",
  "src/components/findings/FindingsDataTableColumns.tsx",
  "src/components/imports/ImportRunEvidenceColumns.tsx",
  "src/components/imports/ImportsWorkbenchHistoryActions.tsx",
  "src/components/projects/ProjectsWorkbenchDirectoryColumns.tsx",
  "src/components/providers/ProvidersWorkbenchSourcesColumns.tsx",
  "src/components/reports/EvidenceCenterHistoryColumns.tsx",
  "src/components/waivers/WaiversWorkbenchRegisterColumns.tsx",
]

const inventoryTableCardContractFiles = [
  "src/components/assets/AssetTable.tsx",
  "src/components/providers/ProvidersWorkbenchSources.tsx",
  "src/components/waivers/WaiversWorkbenchRegister.tsx",
  "src/components/imports/ImportsWorkbenchHistory.tsx",
  "src/components/reports/EvidenceCenterHistory.tsx",
  "src/components/projects/ProjectsWorkbenchDirectory.tsx",
]

const inventoryActionColumnContractFiles = [
  "src/components/assets/AssetTableColumns.tsx",
  "src/components/providers/ProvidersWorkbenchSourcesColumns.tsx",
  "src/components/waivers/WaiversWorkbenchRegisterColumns.tsx",
  "src/components/reports/EvidenceCenterHistoryColumns.tsx",
  "src/components/projects/ProjectsWorkbenchDirectoryColumns.tsx",
]

const splitInventoryActionContractFiles = [
  {
    actions: "src/components/imports/ImportsWorkbenchHistoryActions.tsx",
    columns: "src/components/imports/ImportsWorkbenchHistoryColumns.tsx",
  },
]

const inventoryFilterContractFiles = [
  "src/components/assets/AssetFilters.tsx",
  "src/components/waivers/WaiversWorkbenchRegister.tsx",
  "src/components/projects/ProjectsWorkbenchDirectory.tsx",
]

const filterControlFiles = [
  "src/components/vpw/VpwSearchControl.tsx",
  "src/components/vpw/VpwSelectControl.tsx",
]

const resetControlContractFiles = [
  "src/components/assets/AssetFilters.tsx",
  "src/components/findings/RemediationQueueFilters.tsx",
  "src/components/waivers/WaiversWorkbenchRegister.tsx",
]

const findingsFilterControlContractFiles = [
  "src/components/findings/RemediationQueueProjectSelect.tsx",
  "src/components/findings/RemediationQueueFilterControls.tsx",
  "src/components/findings/RemediationQueueRangeFilter.tsx",
  "src/components/findings/RemediationQueueSavedViews.tsx",
  "src/components/findings/RemediationQueueTableSection.tsx",
]

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

function readShowcaseSources() {
  return [...showcaseFiles].map((path) => readProjectFile(path)).join("\n")
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

function assertSourceOrder(path: string, source: string, tokens: string[]) {
  let cursor = -1
  for (const token of tokens) {
    const next = source.indexOf(token, cursor + 1)
    assert.notEqual(next, -1, `${path} is missing ${token}`)
    assert.ok(
      next > cursor,
      `${path} should keep ${tokens.join(" -> ")} in order`,
    )
    cursor = next
  }
}

function tableCardWrapViolation(path: string, source: string) {
  const tableCardStart = source.indexOf("<VpwTableCard")
  const tableStart = source.indexOf("<VpwDataTable")
  const tableCardEnd = source.lastIndexOf("</VpwTableCard>")

  if (tableCardStart === -1) return `${path}: missing VpwTableCard`
  if (tableStart === -1) return `${path}: missing VpwDataTable`
  if (tableCardEnd === -1) return `${path}: missing VpwTableCard close`
  if (!(tableCardStart < tableStart && tableStart < tableCardEnd)) {
    return `${path}: VpwDataTable is not wrapped by VpwTableCard`
  }
  return null
}

function assertCompactRightAlignedActions(path: string, source: string) {
  assert.match(source, /id:\s*"actions"/, `${path} needs an actions column`)
  assert.match(
    source,
    /headerClassName:\s*"[^"]*text-right[^"]*"/,
    `${path} should right-align the actions header`,
  )
  assert.match(
    source,
    /className:\s*"[^"]*text-right[^"]*"/,
    `${path} should right-align action cells`,
  )
  assert.match(
    source,
    /size="icon-(?:xs|sm)"/,
    `${path} should use compact icon action buttons`,
  )
}

function assertStandardResetControl(path: string, source: string) {
  assert.match(source, /RotateCcw/, `${path} should use the reset icon`)
  assert.match(
    source,
    /<RotateCcw\s+aria-hidden="true"[\s\S]{0,160}\/>\s*Reset\s*</,
    `${path} should pair the reset icon with standard Reset text`,
  )
}

test("semantic badge model keeps focused pure model slices behind its facade", () => {
  const facade = readProjectFile("src/components/vpw/semantic-badge-model.ts")
  const slices = [
    "src/components/vpw/semantic-badge-types.ts",
    "src/components/vpw/semantic-risk-model.ts",
    "src/components/vpw/semantic-status-model.ts",
    "src/components/vpw/semantic-signal-model.ts",
  ]

  assert.deepEqual(
    slices.filter((path) => !existsSync(join(frontendRoot, path))),
    [],
  )
  assert.doesNotMatch(facade, /\b(?:function|const)\s+\w+/)
  assert.match(facade, /from "\.\/semantic-badge-types(?:\.ts)?"/)
  assert.match(facade, /from "\.\/semantic-risk-model(?:\.ts)?"/)
  assert.match(facade, /from "\.\/semantic-status-model(?:\.ts)?"/)
  assert.match(facade, /from "\.\/semantic-signal-model(?:\.ts)?"/)
})

test("semantic risk badges normalize levels, labels, and tones", () => {
  assert.deepEqual(
    [
      normalizeRiskLevel("CRITICAL"),
      normalizeRiskLevel("high"),
      normalizeRiskLevel(" Medium "),
      normalizeRiskLevel("LOW"),
      normalizeRiskLevel("accepted"),
      normalizeRiskLevel("not-a-level"),
      normalizeRiskLevel(null),
    ],
    ["critical", "high", "medium", "low", "accepted", "unknown", "unknown"],
  )

  assert.deepEqual(
    [
      riskLabel("critical"),
      riskLabel("high"),
      riskLabel("medium"),
      riskLabel("low"),
      riskLabel("accepted"),
      riskLabel(undefined),
    ],
    ["Critical", "High", "Medium", "Low", "Accepted", "Unknown"],
  )

  assert.deepEqual(
    [
      riskTone("critical"),
      riskTone("high"),
      riskTone("medium"),
      riskTone("low"),
      riskTone("accepted"),
      riskTone("unknown"),
    ],
    ["critical", "warning", "warning", "info", "success", "neutral"],
  )
})

test("semantic risk scores format consistently across CVSS and percent scales", () => {
  assert.deepEqual(
    [
      formatRiskScore(9.876),
      formatRiskScore("72.34"),
      formatRiskScore(0),
      formatRiskScore(null),
      formatRiskScore(""),
      formatRiskScore("not-a-number"),
    ],
    ["9.9", "72.3", "0.0", "Not scored", "Not scored", "Not scored"],
  )

  assert.deepEqual(
    [
      riskScoreTone(9.1),
      riskScoreTone(7),
      riskScoreTone(4),
      riskScoreTone(3.9),
      riskScoreTone(91),
      riskScoreTone(70),
      riskScoreTone(40),
      riskScoreTone(undefined),
    ],
    [
      "critical",
      "warning",
      "info",
      "neutral",
      "critical",
      "warning",
      "info",
      "neutral",
    ],
  )
})

test("semantic finding statuses map to stable labels and tones", () => {
  assert.deepEqual(
    [
      normalizeStatus("open"),
      normalizeStatus("in-review"),
      normalizeStatus("in progress"),
      normalizeStatus("resolved"),
      normalizeStatus("accepted"),
      normalizeStatus("wont_fix"),
    ],
    ["open", "in_review", "remediating", "fixed", "accepted", "suppressed"],
  )

  assert.deepEqual(
    ["open", "in_review", "remediating", "fixed", "accepted", "suppressed"].map(
      (status) => ({
        label: statusLabel(status),
        tone: statusTone(status),
      }),
    ),
    [
      { label: "Open", tone: "info" },
      { label: "In review", tone: "warning" },
      { label: "Remediating", tone: "warning" },
      { label: "Fixed", tone: "success" },
      { label: "Accepted", tone: "success" },
      { label: "Suppressed", tone: "neutral" },
    ],
  )
})

test("semantic signal badges format labels, aliases, tones, and overflow", () => {
  assert.deepEqual(
    [
      normalizeSignalKind("kev"),
      normalizeSignalKind("_epss"),
      normalizeSignalKind("attack_mapped"),
      normalizeSignalKind("source"),
      normalizeSignalKind("unknown-source"),
    ],
    ["kev", "epss", "attack", "provider", "unknown"],
  )

  assert.deepEqual(
    [
      signalLabel({ kind: "kev" }),
      signalLabel({ kind: "epss", value: 0.934 }),
      signalLabel({ kind: "cvss", value: 9.81 }),
      signalLabel({ kind: "provider", value: "NVD" }),
      signalLabel({ kind: "attack" }),
      signalLabel({ kind: "vex" }),
      signalLabel({ kind: "unknown", value: "Vendor advisory" }),
      signalLabel({ kind: "unknown" }),
    ],
    [
      "KEV",
      "EPSS 93.4%",
      "CVSS 9.8",
      "Provider NVD",
      "ATT&CK mapped",
      "VEX",
      "Vendor advisory",
      "Signal",
    ],
  )

  assert.deepEqual(
    ["kev", "epss", "cvss", "attack", "vex", "provider", "unknown"].map(
      signalTone,
    ),
    ["critical", "info", "info", "support", "support", "info", "neutral"],
  )
  assert.deepEqual(visibleSignalItems(["kev", "epss", "cvss", "vex"], 3), {
    overflowCount: 1,
    visibleItems: ["kev", "epss", "cvss"],
  })
  assert.deepEqual(visibleSignalItems(["kev"], -1), {
    overflowCount: 1,
    visibleItems: [],
  })
})

test("legacy risk and KEV wrappers emit semantic badges without absent placeholders", () => {
  const riskScore = readProjectFile("src/components/risk/RiskScore.tsx")
  const kevBadge = readProjectFile("src/components/risk/KevBadge.tsx")

  assert.doesNotMatch(riskScore, /risk-score-pill/)
  assert.match(riskScore, /RiskScoreBadge/)
  assert.doesNotMatch(kevBadge, />\s*—\s*</)
})

test("badges use centralized density and overflow contracts", () => {
  const badge = readProjectFile("src/components/vpw/VpwBadge.tsx")
  const semanticBadges = readProjectFile(
    "src/components/vpw/VpwSemanticBadges.tsx",
  )
  const badgeStyles = readProjectFile("src/styles/vpw-components.css")
  const rawBadge = readProjectFile("src/components/ui/badge.tsx")
  const remediationFilters = readProjectFile(
    "src/components/findings/RemediationQueueFilters.tsx",
  )

  assert.match(badge, /export type BadgeDensity = "default" \| "compact"/)
  assert.match(badge, /overflow\?: "truncate" \| "wrap"/)
  assert.match(badge, /vpw-badge__label/)
  assert.match(badgeStyles, /--vpw-badge-max-inline-size/)
  assert.match(badgeStyles, /\.vpw-badge--compact/)
  assert.match(badgeStyles, /\.vpw-badge--wrap/)
  assert.match(rawBadge, /max-w-full min-w-0/)

  assert.match(semanticBadges, /density=\{density\}/)
  assert.doesNotMatch(semanticBadges, /vpw-semantic-badge--compact/)
  assert.doesNotMatch(remediationFilters, /h-4 min-w-4 px-1 py-0 text-\[10px\]/)
})

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

test("table row actions use the VPW icon action contract", () => {
  for (const path of rowActionContractFiles) {
    const source = readProjectFile(path)
    assert.match(source, /vpw-table-actions/, `${path} needs action wrapper`)
    assert.match(
      source,
      /vpw-table-action-button/,
      `${path} needs action buttons`,
    )
  }
})

test("inventory data tables use the shared VPW table card shell", () => {
  const offenders = inventoryTableCardContractFiles
    .map((path) => tableCardWrapViolation(path, readProjectFile(path)))
    .filter((violation) => violation !== null)

  assert.deepEqual(offenders, [])

  const tableCard = readProjectFile("src/components/vpw/VpwTableCard.tsx")
  assert.match(tableCard, /titleLevel = 2/)
  assert.match(tableCard, /const TitleTag = titleLevel === 2 \? "h2" : "h3"/)
})

test("inventory action columns stay compact and right aligned", () => {
  for (const path of inventoryActionColumnContractFiles) {
    assertCompactRightAlignedActions(path, readProjectFile(path))
  }
  for (const { actions, columns } of splitInventoryActionContractFiles) {
    assertCompactRightAlignedActions(
      `${columns} + ${actions}`,
      `${readProjectFile(columns)}\n${readProjectFile(actions)}`,
    )
  }
})

test("shared filter bars expose search and select control primitives", () => {
  const missingControls = filterControlFiles.filter(
    (path) => !existsSync(join(frontendRoot, path)),
  )
  assert.deepEqual(missingControls, [])

  const vpwIndex = readProjectFile("src/components/vpw/index.ts")
  assert.match(vpwIndex, /export \* from "\.\/VpwSearchControl"/)
  assert.match(vpwIndex, /export \* from "\.\/VpwSelectControl"/)

  const filterBar = readProjectFile("src/components/vpw/VpwFilterBar.tsx")
  assert.match(filterBar, /VpwSearchControl/)
  assert.doesNotMatch(filterBar, /VpwSearchInput/)
})

test("design-system showcase stays out of the public product barrel", () => {
  const vpwIndex = readProjectFile("src/components/vpw/index.ts")
  const showcaseImportOffenders = walk(srcRoot)
    .filter((path) => !showcaseFiles.has(path))
    .filter((path) => readProjectFile(path).includes("VpwDesignSystemShowcase"))

  assert.doesNotMatch(vpwIndex, /VpwDesignSystemShowcase/)
  assert.deepEqual(showcaseImportOffenders, [])
})

test("filter bars keep the Workbench scope-search-filter-action order", () => {
  const filterBar = readProjectFile("src/components/vpw/VpwFilterBar.tsx")
  assertSourceOrder("src/components/vpw/VpwFilterBar.tsx", filterBar, [
    "vpw-filter-bar__leading",
    "vpw-filter-field--search",
    "vpw-filter-bar__controls",
    "vpw-filter-bar__actions",
  ])

  const assets = readProjectFile("src/components/assets/AssetFilters.tsx")
  assertSourceOrder("src/components/assets/AssetFilters.tsx", assets, [
    'label="Project"',
    'searchTitle="Service"',
    'label="Owner"',
  ])
  assert.match(assets, /searchClassName="vpw-filter-field--md"/)
  assert.match(assets, />\s*Reset\s*</)

  const projects = readProjectFile(
    "src/components/projects/ProjectsWorkbenchDirectory.tsx",
  )
  assert.match(projects, /<VpwFilterBar/)
  assert.match(projects, /searchLabel="Project search"/)
  assert.doesNotMatch(projects, /VpwSearchInput/)

  const waivers = readProjectFile(
    "src/components/waivers/WaiversWorkbenchRegister.tsx",
  )
  assert.match(waivers, /<VpwFilterBar/)
  assert.match(waivers, /leading=\{/)
  assert.match(waivers, /searchLabel="Risk acceptance search"/)
  assert.match(waivers, /actions=\{/)
})

test("inventory filter sections use shared filter controls", () => {
  const offenders: string[] = []

  for (const path of inventoryFilterContractFiles) {
    const source = readProjectFile(path)
    if (!/<VpwFilterBar/.test(source)) {
      offenders.push(`${path}: missing VpwFilterBar`)
    }
    if (/VpwSearchInput/.test(source)) {
      offenders.push(`${path}: uses legacy VpwSearchInput`)
    }
  }

  const assets = readProjectFile("src/components/assets/AssetFilters.tsx")
  if (!/VpwSelectControl/.test(assets)) {
    offenders.push(
      "src/components/assets/AssetFilters.tsx: missing VpwSelectControl",
    )
  }
  if (
    /components\/ui\/(?:input|select)|\.\.\/ui\/(?:input|select)/.test(assets)
  ) {
    offenders.push(
      "src/components/assets/AssetFilters.tsx: imports raw input/select",
    )
  }

  assert.deepEqual(offenders, [])
})

test("findings filter controls share the Workbench control height contract", () => {
  const offenders: string[] = []
  for (const path of findingsFilterControlContractFiles) {
    const source = readProjectFile(path)
    if (!/findings-filter-control/.test(source)) {
      offenders.push(`${path}: missing findings-filter-control`)
    }
  }

  assert.deepEqual(offenders, [])
})

test("filter reset controls use the standard reset icon and text", () => {
  for (const path of resetControlContractFiles) {
    assertStandardResetControl(path, readProjectFile(path))
  }
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
  const showcase = readShowcaseSources()
  const expectedRadius = {
    sm: "4px",
    md: "6px",
    lg: "8px",
    xl: "8px",
    pill: "9999px",
  }

  assert.equal(tokenJson.layout.maxWidth, "2400px")
  assert.deepEqual(tokenJson.radius, expectedRadius)
  assert.match(tokenTs, /maxWidth:\s*"2400px"/)
  assert.match(tokenCss, /--vpw-container-max:\s*2400px;/)
  assert.match(showcase, /2400px max/)

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

test("VpwField associates descriptions and errors with field controls", () => {
  const field = readProjectFile("src/components/vpw/VpwField.tsx")
  const fieldA11y = readProjectFile("src/components/vpw/VpwFieldA11y.ts")
  const fileInput = readProjectFile("src/components/vpw/VpwFileInput.tsx")

  assert.match(field, /from "\.\/VpwFieldA11y"/)
  assert.match(field, /withFieldControlA11y\(children/)
  assert.match(field, /<FieldLabel htmlFor=\{controlId\}/)
  assert.match(field, /aria-hidden="true"/)
  assert.match(field, /<FieldDescription id=\{descriptionId\}/)
  assert.match(field, /<FieldError id=\{errorId\}/)

  assert.match(fieldA11y, /"aria-describedby": mergeIdRefs/)
  assert.match(fieldA11y, /nextProps\["aria-required"\] = true/)
  assert.match(fieldA11y, /nextProps\["aria-invalid"\] = true/)
  assert.match(fieldA11y, /nextProps\["aria-errormessage"\] = errorId/)

  assert.match(fileInput, /aria-describedby=\{ariaDescribedBy\}/)
  assert.match(fileInput, /aria-errormessage=\{ariaErrorMessage\}/)
  assert.match(fileInput, /aria-invalid=\{ariaInvalid\}/)
  assert.match(fileInput, /required=\{ariaRequired === true/)
})
