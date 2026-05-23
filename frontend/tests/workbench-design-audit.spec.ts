import { writeFileSync } from "node:fs"
import { expect, type Locator, type Page, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import { backendBaseUrl, localApiHeaders } from "./workbench-runtime-helpers"

const screenshotViewport = { height: 900, width: 1440 }
const screenshotStepRatio = 0.78

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
  segments: number
  slug: string
}

type ScreenshotManifestEntry = {
  file: string
  route: string
  scroll: {
    clientHeight: number
    maxScroll: number
    scrollHeight: number
    scrollTop: number
  }
  segment: number
  slug: string
}

const auditRoutes: AuditRoute[] = [
  {
    name: "Overview",
    path: ({ project_id }) => `/?projectId=${project_id}`,
    readyText: /Critical Priority|Priority distribution/i,
    segments: 3,
    slug: "overview",
  },
  {
    name: "Triage",
    path: ({ project_id }) => `/findings?projectId=${project_id}`,
    readyText: /Prioritized findings|Findings queue/i,
    segments: 3,
    slug: "triage",
  },
  {
    name: "Finding Detail",
    path: ({ project_id }, findingId) =>
      `/findings/${findingId}?projectId=${project_id}`,
    readyText: /Why this priority\?|Decision core/i,
    segments: 3,
    slug: "finding-detail",
  },
  {
    name: "Imports",
    path: ({ project_id }) => `/imports?projectId=${project_id}`,
    readyText: /Recent Imports|Quick start/i,
    segments: 2,
    slug: "imports",
  },
  {
    name: "New Import",
    path: ({ project_id }) => `/imports/new?projectId=${project_id}`,
    readyText: "Choose source",
    segments: 3,
    slug: "imports-new",
  },
  {
    name: "Supported Formats",
    path: ({ project_id }) => `/imports/formats?projectId=${project_id}`,
    readyText: "CVE list",
    segments: 2,
    slug: "imports-formats",
  },
  {
    name: "Import Run",
    path: ({ latest_run_id, project_id }) =>
      `/imports/runs/${latest_run_id}?projectId=${project_id}`,
    readyText: "Source details",
    segments: 2,
    slug: "imports-run",
  },
  {
    name: "Assets",
    path: ({ project_id }) => `/assets?projectId=${project_id}`,
    readyText: /Asset inventory|Asset register/i,
    segments: 4,
    slug: "assets",
  },
  {
    name: "Data Sources",
    path: ({ project_id }) => `/providers?projectId=${project_id}`,
    readyText: /Provider status|Source inventory/i,
    segments: 2,
    slug: "providers",
  },
  {
    name: "Risk Acceptance",
    path: ({ project_id }) => `/waivers?projectId=${project_id}`,
    readyText: /Decision register|Accepted risk control center/i,
    segments: 4,
    slug: "waivers",
  },
  {
    name: "Evidence Center",
    path: ({ project_id }) => `/reports?projectId=${project_id}`,
    readyText: /Evidence summary|Generated artifacts/i,
    segments: 3,
    slug: "reports",
  },
  {
    name: "Workspace Settings",
    path: ({ project_id }) => `/settings?projectId=${project_id}`,
    readyText: "Workspace state",
    segments: 1,
    slug: "settings",
  },
  {
    name: "Projects",
    path: ({ project_id }) => `/projects?projectId=${project_id}`,
    readyText: /Workspace projects|Projects directory/i,
    segments: 4,
    slug: "projects",
  },
]

test("design audit captures the 36 VPW route section screenshots", async ({
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
    await page.evaluate(() => document.fonts.ready.then(() => undefined))

    const content = page
      .locator('section[aria-label="Workbench page content"]')
      .first()
    await expect(content).toBeVisible()
    await assertRouteDesignContract(page, route)

    for (let segment = 1; segment <= route.segments; segment += 1) {
      const scroll = await scrollRouteSegment(content, route.segments, segment)
      const fileName = `${route.slug}-${String(segment).padStart(2, "0")}.png`
      const file = evidenceScreenshotPath("design-audit", fileName)
      await content.screenshot({ path: file })
      manifest.push({
        file,
        route: route.name,
        scroll,
        segment,
        slug: route.slug,
      })
    }
  }

  expect(manifest).toHaveLength(36)
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

async function scrollRouteSegment(
  content: Locator,
  totalSegments: number,
  segment: number,
) {
  return await content.evaluate(
    (element, args) => {
      const maxScroll = Math.max(0, element.scrollHeight - element.clientHeight)
      const target =
        args.totalSegments === 1
          ? 0
          : Math.min(
              maxScroll,
              Math.round(
                element.clientHeight * args.stepRatio * (args.segment - 1),
              ),
            )
      element.scrollTop = target
      return {
        clientHeight: element.clientHeight,
        maxScroll,
        scrollHeight: element.scrollHeight,
        scrollTop: element.scrollTop,
      }
    },
    { segment, stepRatio: screenshotStepRatio, totalSegments },
  )
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
