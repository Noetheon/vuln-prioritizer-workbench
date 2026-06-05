import { createHash } from "node:crypto"
import { readFileSync, writeFileSync } from "node:fs"
import { expect, type Locator, type Page, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import { backendBaseUrl, localApiHeaders } from "./workbench-runtime-helpers"

const screenshotViewport = { height: 900, width: 1440 }
const screenshotStepRatio = 0.78
const duplicateScrollTolerancePx = 8

type DemoWorkspace = {
  latest_run_id: string
  project_id: string
}

type FindingPage = {
  data: Array<{ id: string }>
}

type AuditRoute = {
  name: string
  path: (workspace: DemoWorkspace, findingId: string) => string
  readyText: RegExp | string
  slug: string
  stableText?: RegExp | string
}

type ScreenshotManifestEntry = {
  file: string
  maxScroll: number
  route: string
  scroll: ScrollMetrics
  segment: number
  sha256: string
  slug: string
  scrollTop: number
}

type ScrollMetrics = {
  clientHeight: number
  maxScroll: number
  scrollHeight: number
  scrollTop: number
}

const auditRoutes: AuditRoute[] = [
  {
    name: "Overview",
    path: ({ project_id }) => `/?projectId=${project_id}`,
    readyText: /Critical Priority|Priority distribution/i,
    slug: "overview",
    stableText: "Top Remediation Queue",
  },
  {
    name: "Triage",
    path: ({ project_id }) => `/findings?projectId=${project_id}`,
    readyText: /Prioritized findings|Findings queue/i,
    slug: "triage",
    stableText: /Showing|CVE-/,
  },
  {
    name: "Finding Detail",
    path: ({ project_id }, findingId) =>
      `/findings/${findingId}?projectId=${project_id}`,
    readyText: /Why this priority\?|Decision core/i,
    slug: "finding-detail",
    stableText: "Recommended action:",
  },
  {
    name: "Imports",
    path: ({ project_id }) => `/imports?projectId=${project_id}`,
    readyText: /Recent Imports|Quick start/i,
    slug: "imports",
    stableText: /Recent Imports|Import history/i,
  },
  {
    name: "New Import",
    path: ({ project_id }) => `/imports/new?projectId=${project_id}`,
    readyText: "Choose source",
    slug: "imports-new",
    stableText: "CVE list",
  },
  {
    name: "Supported Formats",
    path: ({ project_id }) => `/imports/formats?projectId=${project_id}`,
    readyText: "CVE list",
    slug: "imports-formats",
    stableText: "Trivy JSON",
  },
  {
    name: "Import Run",
    path: ({ latest_run_id, project_id }) =>
      `/imports/runs/${latest_run_id}?projectId=${project_id}`,
    readyText: "Source details",
    slug: "imports-run",
    stableText: /Review findings|Diagnostics/,
  },
  {
    name: "Assets",
    path: ({ project_id }) => `/assets?projectId=${project_id}`,
    readyText: /Asset inventory|Asset register/i,
    slug: "assets",
    stableText: /Asset register|analytics-etl-01/,
  },
  {
    name: "Data Sources",
    path: ({ project_id }) => `/providers?projectId=${project_id}`,
    readyText: /Provider status|Source inventory/i,
    slug: "providers",
    stableText: /Source inventory|Provider diagnostics/,
  },
  {
    name: "Risk Acceptance",
    path: ({ project_id }) => `/waivers?projectId=${project_id}`,
    readyText: /Decision register|Accepted risk control center/i,
    slug: "waivers",
    stableText: /DEMO-RISK|No accepted-risk lifecycle debt/,
  },
  {
    name: "Evidence Center",
    path: ({ project_id }) => `/reports?projectId=${project_id}`,
    readyText: /Evidence summary|Generated artifacts/i,
    slug: "reports",
    stableText: /Generated artifacts|evidence-bundle\.zip/,
  },
  {
    name: "Workspace Settings",
    path: ({ project_id }) => `/settings?projectId=${project_id}`,
    readyText: "Workspace state",
    slug: "settings",
    stableText: "Credentials are never displayed",
  },
  {
    name: "Projects",
    path: ({ project_id }) => `/projects?projectId=${project_id}`,
    readyText: /Workspace projects|Projects directory/i,
    slug: "projects",
    stableText: /Projects directory|Online Shop Demo Workspace/,
  },
]

test("design audit captures unique VPW route section screenshots", async ({
  page,
}) => {
  test.setTimeout(180_000)
  await page.setViewportSize(screenshotViewport)

  const workspace = await seedDemoWorkspace(page)
  const findingId = await firstFindingId(page, workspace.project_id)
  const manifest: ScreenshotManifestEntry[] = []

  for (const route of auditRoutes) {
    await page.goto(route.path(workspace, findingId))
    await expect(page.getByRole("main")).toBeVisible()
    await waitForVisibleText(page, route.readyText)
    await waitForStableRouteContent(page, route)
    await page.evaluate(() => document.fonts.ready.then(() => undefined))

    const content = page
      .locator('section[aria-label="Workbench page content"]')
      .first()
    await expect(content).toBeVisible()
    await assertRouteDesignContract(page, route)

    const scrollMetrics = await measureRouteScroll(content)
    const scrollTargets = uniqueScrollTargets(scrollMetrics)
    const routeEntries: ScreenshotManifestEntry[] = []

    for (const [index, scrollTarget] of scrollTargets.entries()) {
      const segment = index + 1
      const scroll = await scrollRouteSegment(content, scrollTarget)
      const fileName = `${route.slug}-${String(segment).padStart(2, "0")}.png`
      const file = evidenceScreenshotPath("design-audit", fileName)
      await content.screenshot({ path: file })
      routeEntries.push({
        file,
        maxScroll: scroll.maxScroll,
        route: route.name,
        scroll,
        segment,
        sha256: screenshotSha256(file),
        slug: route.slug,
        scrollTop: scroll.scrollTop,
      })
    }
    manifest.push(...routeEntries)
  }

  expectRouteCoverage(auditRoutes, manifest)
  expectNoDuplicateAuditSegments(manifest)
  writeFileSync(
    evidenceScreenshotPath("design-audit", "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  )
})

async function seedDemoWorkspace(page: Page): Promise<DemoWorkspace> {
  const response = await page.request.post(
    `${backendBaseUrl}/api/v1/workbench/demo`,
    {
      data: { reset: true },
      headers: localApiHeaders(),
    },
  )
  expect(response.ok()).toBeTruthy()
  const payload = (await response.json()) as Partial<DemoWorkspace>
  expect(payload.project_id).toBeTruthy()
  expect(payload.latest_run_id).toBeTruthy()
  return {
    latest_run_id: payload.latest_run_id ?? "",
    project_id: payload.project_id ?? "",
  }
}

async function firstFindingId(page: Page, projectId: string): Promise<string> {
  const response = await page.request.get(
    `${backendBaseUrl}/api/v1/projects/${projectId}/findings/?limit=1`,
    { headers: localApiHeaders() },
  )
  expect(response.ok()).toBeTruthy()
  const payload = (await response.json()) as FindingPage
  const findingId = payload.data.at(0)?.id
  expect(findingId).toBeTruthy()
  return findingId ?? ""
}

async function waitForVisibleText(page: Page, text: RegExp | string) {
  const matcher =
    typeof text === "string"
      ? { kind: "text", value: text }
      : { flags: text.flags, kind: "regex", value: text.source }

  await page.waitForFunction(
    (serializedMatcher) => {
      const matchesText = (value: string) =>
        serializedMatcher.kind === "text"
          ? value.includes(serializedMatcher.value)
          : new RegExp(serializedMatcher.value, serializedMatcher.flags).test(
              value,
            )
      const isVisible = (element: Element) => {
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return (
          rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden"
        )
      }
      return [...document.body.querySelectorAll("*")].some(
        (element) =>
          isVisible(element) && matchesText(element.textContent ?? ""),
      )
    },
    matcher,
    { timeout: 60_000 },
  )
}

async function waitForStableRouteContent(page: Page, route: AuditRoute) {
  if (route.stableText) {
    await waitForVisibleText(page, route.stableText)
  }

  await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {
    // Some runs keep dev-server bookkeeping requests alive; DOM stability below
    // is the authoritative screenshot gate.
  })

  await page.waitForFunction(
    () => {
      const content = document.querySelector(
        'section[aria-label="Workbench page content"]',
      )
      if (!content) return false

      const visible = (element: Element) => {
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return (
          rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden"
        )
      }

      const visiblePendingSurfaces = [
        ...content.querySelectorAll('[data-slot="skeleton"], .animate-pulse'),
      ].filter(visible)
      if (visiblePendingSurfaces.length > 0) return false

      const visibleLoadingText = [...content.querySelectorAll("*")]
        .filter(visible)
        .some((element) =>
          /^(?:Loading|Loading\.\.\.)$/i.test(
            (element.textContent ?? "").trim(),
          ),
        )

      return !visibleLoadingText
    },
    {},
    { timeout: 60_000 },
  )
}

async function measureRouteScroll(content: Locator) {
  return await content.evaluate((element) => {
    const maxScroll = Math.max(0, element.scrollHeight - element.clientHeight)
    return {
      clientHeight: element.clientHeight,
      maxScroll,
      scrollHeight: element.scrollHeight,
      scrollTop: element.scrollTop,
    }
  })
}

function uniqueScrollTargets(metrics: ScrollMetrics) {
  if (metrics.maxScroll <= duplicateScrollTolerancePx) {
    return [0]
  }

  const step = Math.max(
    1,
    Math.round(metrics.clientHeight * screenshotStepRatio),
  )
  const candidates = [0]
  for (
    let target = step;
    target < metrics.maxScroll;
    target += step
  ) {
    candidates.push(target)
  }
  candidates.push(metrics.maxScroll)

  return candidates.reduce<number[]>((targets, candidate) => {
    const clamped = Math.min(metrics.maxScroll, Math.max(0, candidate))
    const previous = targets.at(-1)
    if (
      previous === undefined ||
      Math.abs(clamped - previous) > duplicateScrollTolerancePx
    ) {
      targets.push(clamped)
    }
    return targets
  }, [])
}

async function scrollRouteSegment(content: Locator, scrollTop: number) {
  return await content.evaluate(
    (element, args) => {
      const maxScroll = Math.max(0, element.scrollHeight - element.clientHeight)
      const target = Math.min(maxScroll, Math.max(0, args.scrollTop))
      element.scrollTop = target
      return {
        clientHeight: element.clientHeight,
        maxScroll,
        scrollHeight: element.scrollHeight,
        scrollTop: element.scrollTop,
      }
    },
    { scrollTop },
  )
}

function screenshotSha256(file: string) {
  return createHash("sha256").update(readFileSync(file)).digest("hex")
}

function expectRouteCoverage(
  routes: readonly AuditRoute[],
  manifest: readonly ScreenshotManifestEntry[],
) {
  for (const route of routes) {
    const routeEntries = manifest.filter((entry) => entry.slug === route.slug)
    expect(
      routeEntries.length,
      `${route.name} should capture at least one design-audit segment`,
    ).toBeGreaterThan(0)
    expect(
      routeEntries[0]?.scrollTop,
      `${route.name} should begin at the top of the scroll container`,
    ).toBe(0)

    const maxScroll = Math.max(...routeEntries.map((entry) => entry.maxScroll))
    if (maxScroll > duplicateScrollTolerancePx) {
      expect(
        routeEntries.some(
          (entry) =>
            Math.abs(entry.scrollTop - maxScroll) <=
            duplicateScrollTolerancePx,
        ),
        `${route.name} should include the terminal scroll position`,
      ).toBeTruthy()
    }
  }
}

function expectNoDuplicateAuditSegments(
  manifest: readonly ScreenshotManifestEntry[],
) {
  const slugs = new Set(manifest.map((entry) => entry.slug))
  for (const slug of slugs) {
    const routeEntries = manifest.filter((entry) => entry.slug === slug)
    const seenScrollTops: number[] = []
    const seenHashes = new Set<string>()

    for (const entry of routeEntries) {
      expect(
        seenScrollTops.some(
          (scrollTop) =>
            Math.abs(scrollTop - entry.scrollTop) <=
            duplicateScrollTolerancePx,
        ),
        `${entry.route} has a duplicate scroll segment at ${entry.scrollTop}px`,
      ).toBe(false)
      seenScrollTops.push(entry.scrollTop)

      expect(
        seenHashes.has(entry.sha256),
        `${entry.route} has duplicate screenshot content at segment ${entry.segment}`,
      ).toBe(false)
      seenHashes.add(entry.sha256)
    }
  }
}

async function assertRouteDesignContract(page: Page, route: AuditRoute) {
  const metrics = await page.evaluate(() => {
    const content = document.querySelector(
      'section[aria-label="Workbench page content"]',
    )
    const visible = (element: Element) => {
      const rect = element.getBoundingClientRect()
      const style = getComputedStyle(element)
      return (
        rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden"
      )
    }
    const isContentSurface = (tag: string, className: string) => {
      if (["a", "button", "input", "select", "textarea"].includes(tag)) {
        return false
      }
      return /(?:vpw-card|vpw-panel|card|panel|hero|summary|register|table-card|command-panel)/i.test(
        className,
      )
    }
    const hasVisibleRaisedShadow = (boxShadow: string) =>
      boxShadow !== "none" &&
      !boxShadow.includes("inset") &&
      /[1-9]\d*px/.test(boxShadow)
    const contentElements = [...(content?.querySelectorAll("*") ?? [])].filter(
      visible,
    )
    const raisedShadows = contentElements
      .map((element) => ({
        boxShadow: getComputedStyle(element).boxShadow,
        className: String((element as HTMLElement).className),
        tag: element.tagName.toLowerCase(),
      }))
      .filter(
        (item) =>
          isContentSurface(item.tag, item.className) &&
          item.boxShadow &&
          hasVisibleRaisedShadow(item.boxShadow),
      )
    const headingSizes = [
      ...(content?.querySelectorAll("h2,h3") ?? []),
    ].flatMap((element) =>
      visible(element)
        ? [Number.parseFloat(getComputedStyle(element).fontSize)]
        : [],
    )
    return {
      bodyScrollWidth: document.body.scrollWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      headingMax: Math.max(0, ...headingSizes),
      raisedShadows,
      viewportWidth: document.documentElement.clientWidth,
    }
  })

  expect(
    metrics.documentScrollWidth,
    `${route.slug} document horizontal overflow`,
  ).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(
    metrics.bodyScrollWidth,
    `${route.slug} body horizontal overflow`,
  ).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(
    metrics.headingMax,
    `${route.slug} route-local heading scale`,
  ).toBeLessThanOrEqual(24)
  expect(metrics.raisedShadows, `${route.slug} raised content shadows`).toEqual(
    [],
  )
}
