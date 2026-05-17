import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { dirname, join } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

import {
  routeDetailFromPathname,
  workbenchPathFromPathname,
} from "../src/lib/app-route-config.ts"

const frontendRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const appRouterFile = new URL("../src/AppRouter.tsx", import.meta.url)
const generatedRouteTreeFile = new URL("../src/routeTree.gen.ts", import.meta.url)
const oldRoutesDir = new URL("../src/routes/", import.meta.url)
const routeErrorBoundaryFile = new URL(
  "../src/workbench/RouteErrorBoundary.tsx",
  import.meta.url,
)
const workbenchShellFile = new URL(
  "../src/workbench/WorkbenchShell.tsx",
  import.meta.url,
)
const workbenchRoutesDir = new URL("../src/workbench/routes/", import.meta.url)
const componentsDir = join(frontendRoot, "src/components")
const appShellFile = new URL("../src/components/app/AppShell.tsx", import.meta.url)
const packageJsonFile = new URL("../package.json", import.meta.url)
const routeDetailsFile = new URL(
  "../src/lib/app-route-config.ts",
  import.meta.url,
)
const workbenchNavigationFile = new URL(
  "../src/lib/workbench-navigation.ts",
  import.meta.url,
)

function text(url: URL) {
  return readFileSync(url, "utf8")
}

function uniqueMatches(source: string, pattern: RegExp) {
  return [...new Set([...source.matchAll(pattern)].map((match) => match[1]))]
}

function tsxFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) return tsxFiles(path)
      return path.endsWith(".tsx") ? [path] : []
    })
    .sort()
}

test("AppRouter owns the active Workbench route table", () => {
  const appRouter = text(appRouterFile)
  const workbenchNavigation = text(workbenchNavigationFile)
  const workbenchPaths = uniqueMatches(workbenchNavigation, /\|\s+"([^"]+)"/g)
    .sort()
  const navigationPaths = uniqueMatches(
    workbenchNavigation,
    /\{\s*label:\s*"[^"]+",\s*icon:\s*[^,]+,\s*to:\s*"([^"]+)"/g,
  ).sort()
  const routerPaths = uniqueMatches(appRouter, /^\s+"([^"]+)":\s+\{/gm)
    .sort()

  assert.deepEqual(navigationPaths, workbenchPaths)
  assert.deepEqual(routerPaths, workbenchPaths)
  assert.match(appRouter, /const importRunMatch = normalizedPath\.match/)
  assert.match(appRouter, /params: \{ importsView: "new" \}/)
  assert.match(appRouter, /params: \{ importsView: "formats" \}/)
  assert.match(appRouter, /params: \{ importsView: "run", runId \}/)
  assert.match(appRouter, /routePath: "\/imports"/)
  assert.match(appRouter, /const findingDetailMatch = normalizedPath\.match/)
  assert.match(appRouter, /routePath: "\/findings"/)
})

test("AppRouter lazy imports existing Workbench route containers", () => {
  const appRouter = text(appRouterFile)
  const lazyModules = uniqueMatches(
    appRouter,
    /import\("\.\/workbench\/routes\/([^"]+)"\)/g,
  )
  const routeFiles = readdirSync(workbenchRoutesDir)

  for (const moduleName of lazyModules) {
    assert.ok(
      routeFiles.includes(`${moduleName}.tsx`),
      `AppRouter imports missing Workbench route module ${moduleName}`,
    )
  }
})

test("WorkbenchPath, navigation, and route details stay in sync", () => {
  const routeDetails = text(routeDetailsFile)
  const workbenchNavigation = text(workbenchNavigationFile)
  const workbenchPaths = uniqueMatches(workbenchNavigation, /\|\s+"([^"]+)"/g)
    .sort()
  const navigationPaths = uniqueMatches(
    workbenchNavigation,
    /\{\s*label:\s*"[^"]+",\s*icon:\s*[^,]+,\s*to:\s*"([^"]+)"/g,
  ).sort()
  const routeDetailPaths = uniqueMatches(routeDetails, /^\s+"([^"]+)":\s+\{/gm)
    .sort()

  assert.deepEqual(navigationPaths, workbenchPaths)
  assert.deepEqual(routeDetailPaths, workbenchPaths)
  assert.doesNotMatch(routeDetails, /components\/app\/AppShell/)
  assert.doesNotMatch(
    `${routeDetails}\n${text(appShellFile)}`,
    /workbenchNavigation|LoginService|UsersService|ApiTokensService/,
  )
})

test("obsolete file-route scaffolding is not part of the active frontend", () => {
  assert.equal(existsSync(oldRoutesDir), false)
  assert.equal(existsSync(generatedRouteTreeFile), false)
})

test("Workbench shell is mounted once by AppRouter", () => {
  const appRouter = text(appRouterFile)
  assert.match(appRouter, /<WorkbenchShell routePath=\{match\.routePath\}>/)
  assert.match(appRouter, /<RouteParamsProvider params=\{match\.params\}>/)

  for (const file of readdirSync(workbenchRoutesDir).filter((item) =>
    item.endsWith(".tsx"),
  )) {
    const source = text(new URL(file, workbenchRoutesDir))
    assert.doesNotMatch(
      source,
      /WorkbenchShell/,
      `${file} should rely on AppRouter for the shell`,
    )
  }
})

test("finding route decoding and lazy routes fail closed", () => {
  const appRouter = text(appRouterFile)
  const routeErrorBoundary = text(routeErrorBoundaryFile)
  const workbenchShell = text(workbenchShellFile)

  assert.match(appRouter, /safeDecodeURIComponent/)
  assert.match(appRouter, /findingId === null/)
  assert.doesNotMatch(appRouter, /decodeURIComponent\(findingDetailMatch/)
  assert.match(workbenchShell, /<RouteErrorBoundary/)
  assert.match(workbenchShell, /key=\{location\.pathname\}/)
  assert.match(workbenchShell, /resetKey=\{`\$\{location\.pathname\}\$\{location\.searchStr\}`\}/)
  assert.match(workbenchShell, /<Suspense fallback=/)
  assert.match(routeErrorBoundary, /Workbench route failed to render/)
})

test("AppShell handles blocked storage and restores route focus", () => {
  const appShell = text(appShellFile)

  assert.match(appShell, /function readSidebarCollapsed/)
  assert.match(appShell, /try \{\s*return window\.localStorage\.getItem/s)
  assert.match(appShell, /function writeSidebarCollapsed/)
  assert.match(appShell, /catch \{/)
  assert.match(appShell, /contentRef/)
  assert.match(appShell, /content\.scrollTop = 0/)
  assert.match(appShell, /content\.focus\(\{ preventScroll: true \}\)/)
})

test("Workbench route matching does not highlight dashboard for unknown paths", () => {
  assert.equal(workbenchPathFromPathname("/"), "/")
  assert.equal(workbenchPathFromPathname("/imports/new"), "/imports")
  assert.equal(workbenchPathFromPathname("/imports/runs/run-2"), "/imports")
  assert.equal(workbenchPathFromPathname("/imports/formats"), "/imports")
  assert.equal(workbenchPathFromPathname("/findings/demo-f1"), "/findings")
  assert.equal(workbenchPathFromPathname("/reports/exported/123"), "/reports")
  assert.equal(workbenchPathFromPathname("/findings-old"), null)
  assert.equal(workbenchPathFromPathname("/unknown"), null)
})

test("route details specialize finding detail and unknown paths", () => {
  assert.equal(
    routeDetailFromPathname("/findings/finding-1", "/findings").title,
    "Finding detail",
  )
  assert.equal(routeDetailFromPathname("/imports/new", "/imports").title, "New import")
  assert.equal(
    routeDetailFromPathname("/imports/runs/run-2", "/imports").title,
    "Import run run-2",
  )
  assert.equal(
    routeDetailFromPathname("/imports/formats", "/imports").title,
    "Supported formats",
  )
  assert.equal(routeDetailFromPathname("/unknown", null).title, "Workspace")
})

test("frontend unit test scripts automatically include every unit test file", () => {
  const packageJson = JSON.parse(text(packageJsonFile)) as {
    scripts: Record<string, string>
  }

  for (const scriptName of ["test:unit", "test:unit:coverage"]) {
    const script = packageJson.scripts[scriptName]
    assert.match(script, /\btests\/\*\.test\.ts\b/)
    assert.doesNotMatch(script, /tests\/[\w-]+\.test\.ts/)
    assert.doesNotMatch(script, /\.spec\.ts/)
  }
  assert.equal(packageJson.scripts["test:types"], "tsc -p tsconfig.tests.json")
})

test("finding detail links preserve selected project context", () => {
  const sourceFiles = [
    ...tsxFiles(componentsDir),
    ...tsxFiles(fileURLToPath(workbenchRoutesDir)),
  ]
  const missingProjectSearch = sourceFiles.flatMap((file) => {
    const source = readFileSync(file, "utf8")
    const links = [
      ...source.matchAll(
        /<Link\b(?=[^>]*\bto="\/findings\/\$findingId")(?=[^>]*\bparams=\{\{\s*findingId:)[^>]*>/gs,
      ),
    ]
    return links
      .filter((match) => !/\bsearch=/.test(match[0]))
      .map(() => file.replace(`${frontendRoot}/`, ""))
  })

  assert.deepEqual(missingProjectSearch, [])
})
