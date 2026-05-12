import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import test from "node:test"

import { workbenchPathFromPathname } from "../src/lib/app-route-config.ts"

const appRouterFile = new URL("../src/AppRouter.tsx", import.meta.url)
const oldRoutesDir = new URL("../src/routes/", import.meta.url)
const workbenchRoutesDir = new URL("../src/workbench/routes/", import.meta.url)
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

test("Workbench route matching does not highlight dashboard for unknown paths", () => {
  assert.equal(workbenchPathFromPathname("/"), "/")
  assert.equal(workbenchPathFromPathname("/findings/demo-f1"), "/findings")
  assert.equal(workbenchPathFromPathname("/reports/exported/123"), "/reports")
  assert.equal(workbenchPathFromPathname("/findings-old"), null)
  assert.equal(workbenchPathFromPathname("/unknown"), null)
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
})
