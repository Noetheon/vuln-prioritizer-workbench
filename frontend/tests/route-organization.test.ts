import assert from "node:assert/strict"
import { readFileSync, readdirSync } from "node:fs"
import test from "node:test"

import { workbenchPathFromPathname } from "../src/lib/app-route-config.ts"

const routesDir = new URL("../src/routes/_layout/", import.meta.url)
const authenticatedLayoutFile = new URL("../src/routes/_layout.tsx", import.meta.url)
const workbenchRoutesDir = new URL("../src/workbench/routes/", import.meta.url)
const appShellFile = new URL("../src/components/app/AppShell.tsx", import.meta.url)
const packageJsonFile = new URL("../package.json", import.meta.url)
const routeDetailsFile = new URL(
  "../src/lib/app-route-config.ts",
  import.meta.url,
)

function text(url: URL) {
  return readFileSync(url, "utf8")
}

function uniqueMatches(source: string, pattern: RegExp) {
  return [...new Set([...source.matchAll(pattern)].map((match) => match[1]))]
}

function routePathFromAdapter(source: string) {
  const routePath = source.match(/createFileRoute\("([^"]+)"\)/)?.[1] ?? ""
  if (!routePath.startsWith("/_layout")) {
    return null
  }
  const publicPath = routePath.replace("/_layout", "") || "/"
  return publicPath === "/" ? "/" : publicPath
}

test("authenticated route adapters only import Workbench route containers", () => {
  const routeFiles = readdirSync(routesDir).filter((file) => file.endsWith(".tsx"))

  for (const file of routeFiles) {
    const source = text(new URL(file, routesDir))
    const imports = uniqueMatches(source, /^import .* from "([^"]+)"/gm)
      .filter((specifier) => specifier.startsWith("../"))

    assert.deepEqual(
      imports.filter((specifier) => !specifier.startsWith("../../workbench/routes/")),
      [],
      `${file} should not import feature components directly`,
    )
  }
})

test("authenticated route adapters map to existing Workbench route containers", () => {
  const routeFiles = readdirSync(routesDir).filter((file) => file.endsWith(".tsx"))

  for (const file of routeFiles) {
    const source = text(new URL(file, routesDir))
    const routeImport = source.match(
      /^import \{ ([^}]+) \} from "\.\.\/\.\.\/workbench\/routes\/([^"]+)"/m,
    )
    assert.ok(routeImport, `${file} should import a Workbench route container`)
    const [, componentName, moduleName] = routeImport
    assert.ok(
      readdirSync(workbenchRoutesDir).includes(`${moduleName}.tsx`),
      `${file} imports missing Workbench route module ${moduleName}`,
    )
    assert.match(
      source,
      new RegExp(`component:\\s*${componentName}`),
      `${file} should mount its imported route container directly`,
    )
  }
})

test("WorkbenchPath, navigation, route details, and route adapters stay in sync", () => {
  const appShell = text(appShellFile)
  const routeDetails = text(routeDetailsFile)
  const workbenchPaths = uniqueMatches(appShell, /\|\s+"([^"]+)"/g).sort()
  const navigationPaths = uniqueMatches(
    appShell,
    /\{\s*label:\s*"[^"]+",\s*icon:\s*[^,]+,\s*to:\s*"([^"]+)"/g,
  ).sort()
  const routeDetailPaths = uniqueMatches(routeDetails, /^\s+"([^"]+)":\s+\{/gm)
    .sort()
  const adapterPaths = readdirSync(routesDir)
    .filter((file) => file.endsWith(".tsx"))
    .map((file) => routePathFromAdapter(text(new URL(file, routesDir))))
    .filter((path): path is string => Boolean(path) && !path.includes("$"))
    .sort()

  assert.deepEqual(navigationPaths, workbenchPaths)
  assert.deepEqual(routeDetailPaths, workbenchPaths)
  assert.deepEqual(adapterPaths, workbenchPaths)
})

test("Workbench shell is mounted once at the authenticated layout boundary", () => {
  const layoutSource = text(authenticatedLayoutFile)
  assert.match(layoutSource, /<WorkbenchShell>\s*<Outlet \/>/s)

  for (const file of readdirSync(workbenchRoutesDir).filter((item) =>
    item.endsWith(".tsx"),
  )) {
    const source = text(new URL(file, workbenchRoutesDir))
    assert.doesNotMatch(
      source,
      /WorkbenchShell/,
      `${file} should rely on the authenticated layout shell`,
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
