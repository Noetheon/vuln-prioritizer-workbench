import { expect, test } from "@playwright/test"

const validOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
    "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public",
  ].join("\n"),
)

test("template waiver workflow keeps accepted risk visible", async ({
  page,
}) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW Waiver Project ${testRunSuffix}`

  await page.goto("/login")
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page).toHaveURL(/\/$/)

  const accessToken = await page.evaluate(() =>
    window.localStorage.getItem("access_token"),
  )
  expect(accessToken).toBeTruthy()
  const authHeaders = { Authorization: `Bearer ${accessToken}` }

  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright waiver project",
        name: projectName,
      },
      headers: authHeaders,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string }

  const importResponse = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers: authHeaders,
      multipart: {
        file: {
          buffer: validOccurrenceCsv,
          mimeType: "text/csv",
          name: "waiver-occurrences.csv",
        },
        input_type: "generic-occurrence-csv",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()

  await page.goto("/waivers")
  await expect(page.getByRole("link", { name: "Waivers" })).toBeVisible()
  await page.getByLabel("Waivers project").selectOption(project.id)

  const createWaiver = page.getByRole("region", { name: "Create waiver" })
  await createWaiver.getByLabel("Waiver CVE ID").fill("CVE-2024-3094")
  await createWaiver.getByLabel("Waiver owner").fill("risk-owner")
  await createWaiver
    .getByLabel("Waiver reason")
    .fill("Temporary accepted risk for VPW-064 browser evidence.")
  await createWaiver.getByLabel("Waiver expires at").fill("2099-12-31")
  await createWaiver.getByLabel("Waiver review at").fill("2099-12-01")
  await createWaiver.getByLabel("Waiver approval reference").fill("CAB-064")
  await createWaiver.getByRole("button", { name: "Create waiver" }).click()

  const waiversTable = page.getByRole("table", { name: "Waivers table" })
  await expect(waiversTable).toContainText("CVE-2024-3094")
  await expect(waiversTable).toContainText("risk-owner")
  await expect(waiversTable).toContainText("Active")
  await expect(waiversTable).toContainText("CAB-064")

  const findingsResponse = await page.request.get(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers: authHeaders },
  )
  expect(findingsResponse.ok()).toBeTruthy()
  const findingsPayload = (await findingsResponse.json()) as {
    data: Array<{ cve_id: string; id: string }>
  }
  const finding = findingsPayload.data.find(
    (item) => item.cve_id === "CVE-2024-3094",
  )
  expect(finding?.id).toBeTruthy()

  await page.goto(`/findings/${finding?.id}`)
  const findingDetail = page.getByRole("region", {
    exact: true,
    name: "Finding detail",
  })
  await expect(findingDetail).toContainText("Accepted")
  const acceptedRisk = page.getByRole("region", { name: "Accepted risk" })
  await expect(acceptedRisk).toContainText("risk-owner")
  await expect(acceptedRisk).toContainText("Temporary accepted risk")
  await expect(acceptedRisk).toContainText("2099-12-31")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-064-waiver-risk-acceptance.png",
  })

  await page.goto("/waivers")
  await page.getByLabel("Waivers project").selectOption(project.id)
  await waiversTable.getByRole("button", { name: "Expire" }).click()
  await expect(waiversTable).toContainText("Expired")

  await page.goto(`/findings/${finding?.id}`)
  await expect(page.getByRole("region", { name: "Accepted risk" })).toHaveCount(
    0,
  )
})
