import { expect, test } from "@playwright/test"
import { authHeaders, backendBaseUrl, login } from "./auth-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  cyclonedxVex,
  cyclonedxVexOccurrenceCsv,
} from "./workbench-e2e-helpers"

test("workbench frontend renders CycloneDX VEX occurrence evidence", async ({
  page,
}) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW CycloneDX VEX ${testRunSuffix}`

  const accessToken = await login(page)
  const headers = authHeaders(accessToken)
  const projectResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/`,
    {
      data: {
        description: "Playwright CycloneDX VEX project",
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
          buffer: cyclonedxVexOccurrenceCsv,
          mimeType: "text/csv",
          name: "cyclonedx-vex-occurrence.csv",
        },
        input_type: "generic-occurrence-csv",
        vex_file: {
          buffer: cyclonedxVex,
          mimeType: "application/json",
          name: "cyclonedx-vex.json",
        },
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
    data: Array<{
      cve_id: string
      id: string
      status?: string
      suppressed_by_vex?: boolean
    }>
  }
  const suppressed = findingsPayload.data.find(
    (finding) => finding.cve_id === "CVE-2023-34362",
  )
  expect(suppressed).toBeTruthy()
  if (!suppressed) {
    throw new Error("Expected CycloneDX VEX-suppressed finding.")
  }
  expect(suppressed.suppressed_by_vex).toBe(true)
  expect(suppressed.status).toBe("suppressed")
  await page.goto(`/findings/${suppressed.id}`)
  const occurrencesTable = page.getByRole("table", {
    name: "Occurrences table",
  })
  await expect(occurrencesTable).toContainText("Not Affected")
  await expect(occurrencesTable).not.toContainText(
    "vulnerable_code_not_present",
  )
  await expect(occurrencesTable).toContainText(
    "pkg:pypi/moveit-transfer@2023.0.0",
  )
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-066-cyclonedx-vex-parser.png"),
  })
})
