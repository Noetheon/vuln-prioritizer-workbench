import { expect, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  backendBaseUrl,
  localApiHeaders,
  openWorkbench,
} from "./workbench-runtime-helpers"
import { selectDashboardProject, validCveList } from "./workbench-e2e-helpers"

test("workbench finding detail renders TTP Context tab", async ({ page }) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW TTP Context ${testRunSuffix}`

  await openWorkbench(page)
  const headers = localApiHeaders()
  const projectResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/`,
    {
      data: {
        description: "Playwright TTP Context project",
        name: projectName,
      },
      headers,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string }

  const importResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/${project.id}/imports`,
    {
      headers,
      multipart: {
        file: {
          buffer: validCveList,
          mimeType: "text/plain",
          name: "cves.txt",
        },
        input_type: "cve-list",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()

  const findingsResponse = await page.request.get(
    `${backendBaseUrl}/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers },
  )
  expect(findingsResponse.ok()).toBeTruthy()
  const findingsPayload = (await findingsResponse.json()) as {
    data: Array<{ cve_id: string; id: string }>
  }
  const finding = findingsPayload.data.find(
    (item) => item.cve_id === "CVE-2024-3094",
  )
  expect(finding?.id).toBeTruthy()
  if (!finding?.id) {
    throw new Error("Expected CVE-2024-3094 finding to exist.")
  }

  await page.goto("/")
  await selectDashboardProject(page, projectName)
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-059-attack-summary-dashboard.png"),
  })

  await page.goto(`/findings/${finding.id}`)
  await expect(
    page.getByRole("heading", { name: "CVE-2024-3094" }),
  ).toBeVisible()
  await page.getByRole("tab", { name: "TTP Context" }).click()
  const ttpPanel = page.getByRole("tabpanel", { name: "TTP Context" })
  await expect(ttpPanel).toContainText("Defensive context")
  await expect(ttpPanel).toContainText(
    "No approved ATT&CK mapping is stored for this finding.",
  )
  await expect(ttpPanel).toContainText(
    "Workbench does not infer tactics or techniques for unmapped CVEs.",
  )
  await expect(ttpPanel).toContainText(
    "No exploit steps, payloads, PoC guidance, active probing, or offensive procedure instructions.",
  )
  await expect(ttpPanel).not.toContainText(
    /generate PoC|run PoC|autopatch|start active probing|exploit payload/i,
  )
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-058-ttp-context-tab.png"),
  })
})
