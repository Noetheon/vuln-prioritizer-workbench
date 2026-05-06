import { expect, type Locator, type Page, test } from "@playwright/test"
import { authHeaders, login } from "./auth-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"

const validOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
    "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public",
  ].join("\n"),
)

const governanceOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure,environment",
    "CVE-2024-3094,payments-api,xz,5.6.0,pkg:apk/alpine/xz@5.6.0,CRITICAL,platform,checkout,public,production",
    "CVE-2024-4577,payments-worker,php-cgi,8.3.7,pkg:deb/debian/php-cgi@8.3.7,HIGH,platform,checkout,internal,production",
    "CVE-2024-3094,identity-api,xz,5.6.0-r1,pkg:apk/alpine/xz@5.6.0-r1,CRITICAL,appsec,identity,internal,production",
  ].join("\n"),
)

function dateValueFromOffset(days: number) {
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString().slice(0, 10)
}

async function selectRadixOption(
  page: Page,
  trigger: Locator,
  optionName: string | RegExp,
) {
  await expect(trigger).toBeVisible()
  await trigger.click()
  if (typeof optionName === "string") {
    const option = page.getByRole("option", { exact: true, name: optionName })
    await expect(option).toBeAttached()
    await option.evaluate((element) => {
      const target = element as HTMLElement
      let parent = target.parentElement
      while (parent) {
        if (parent.scrollHeight > parent.clientHeight) {
          parent.scrollTop = target.offsetTop - parent.clientHeight / 2
          break
        }
        parent = parent.parentElement
      }
      target.scrollIntoView({ block: "nearest" })
    })
    try {
      await option.click({ timeout: 3000 })
    } catch {
      await option.dispatchEvent("pointerdown")
      await option.dispatchEvent("pointerup")
      await option.dispatchEvent("click")
    }
    return
  }
  const option = page.getByRole("option", { name: optionName })
  try {
    await option.scrollIntoViewIfNeeded({ timeout: 1000 })
    await option.click({ timeout: 3000 })
  } catch {
    await option.click({ force: true })
  }
}

async function selectRadixOptionByLabel(
  page: Page,
  scope: Page | Locator,
  label: string,
  optionName: string | RegExp,
) {
  await selectRadixOption(
    page,
    scope.getByRole("combobox", { exact: true, name: label }),
    optionName,
  )
}

async function selectDashboardProject(page: Page, projectName: string) {
  const projectTrigger = page.getByRole("combobox").first()
  await selectRadixOption(page, projectTrigger, projectName)
  await expect(projectTrigger).toContainText(projectName)
}

test("template waiver workflow keeps accepted risk visible", async ({
  page,
}) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW Waiver Project ${testRunSuffix}`

  const accessToken = await login(page)
  const headers = authHeaders(accessToken)

  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright waiver project",
        name: projectName,
      },
      headers,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string }

  const importResponse = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers,
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
  expect(importResponse.ok(), await importResponse.text()).toBeTruthy()

  await page.goto("/waivers")
  await expect(page.getByRole("link", { name: "Waivers" })).toBeVisible()
  await selectRadixOptionByLabel(page, page, "Waivers project", projectName)

  await expect(page.getByText("Create waiver").first()).toBeVisible()
  const createWaiver = page
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

  await page.goto(`/findings/${finding?.id}`)
  const findingDetail = page.getByRole("region", {
    name: "Finding priority decision",
  })
  await expect(findingDetail).toContainText("Accepted")
  await expect(findingDetail).toContainText("Risk acceptance option")
  await expect(findingDetail).toContainText("Temporary accepted risk")
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-064-waiver-risk-acceptance.png"),
  })

  await page.goto("/waivers")
  await selectRadixOptionByLabel(page, page, "Waivers project", projectName)
  await waiversTable.getByRole("button", { name: "Expire" }).click()
  await expect(waiversTable).toContainText("Expired")

  await page.goto(`/findings/${finding?.id}`)
  await expect(page.getByText("Temporary accepted risk")).toHaveCount(0)
})

test("template governance rollups show service risk and waiver debt", async ({
  page,
}) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW Governance Project ${testRunSuffix}`

  const accessToken = await login(page)
  const headers = authHeaders(accessToken)

  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright governance rollup project",
        name: projectName,
      },
      headers,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string }

  const importResponse = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers,
      multipart: {
        file: {
          buffer: governanceOccurrenceCsv,
          mimeType: "text/csv",
          name: "governance-occurrences.csv",
        },
        input_type: "generic-occurrence-csv",
      },
    },
  )
  expect(importResponse.ok(), await importResponse.text()).toBeTruthy()

  const reviewDueWaiver = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/waivers/`,
    {
      data: {
        approval_ref: "CAB-067-A",
        expires_at: dateValueFromOffset(7),
        owner: "risk-team",
        reason: "Review due checkout waiver for VPW-067 evidence.",
        review_at: dateValueFromOffset(0),
        service: "checkout",
      },
      headers,
    },
  )
  expect(reviewDueWaiver.ok(), await reviewDueWaiver.text()).toBeTruthy()

  const expiredWaiver = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/waivers/`,
    {
      data: {
        approval_ref: "CAB-067-B",
        asset_key: "identity-api",
        expires_at: dateValueFromOffset(-1),
        owner: "legacy-risk",
        reason: "Expired identity waiver for VPW-067 debt evidence.",
        review_at: dateValueFromOffset(-2),
      },
      headers,
    },
  )
  expect(expiredWaiver.ok(), await expiredWaiver.text()).toBeTruthy()

  const rollupsResponse = await page.request.get(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/governance/rollups/`,
    { headers },
  )
  expect(rollupsResponse.ok()).toBeTruthy()
  const rollups = (await rollupsResponse.json()) as {
    top_services_by_risk: Array<{ label: string; finding_count: number }>
    waiver_debt: { expired_count: number; review_due_count: number }
  }
  expect(rollups.top_services_by_risk[0]).toMatchObject({
    finding_count: 2,
    label: "checkout",
  })
  expect(rollups.waiver_debt).toMatchObject({
    expired_count: 1,
    review_due_count: 1,
  })

  await page.goto("/")
  await selectDashboardProject(page, projectName)
  await page.getByRole("tab", { name: "Top Services" }).click()
  await expect(page.getByText("Top Services by Risk")).toBeVisible()
  await expect(page.getByText("checkout").first()).toBeVisible()
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-067-top-services-by-risk.png"),
  })

  await page.goto("/waivers")
  await selectRadixOptionByLabel(page, page, "Waivers project", projectName)
  await expect(page.getByText("Owner follow-up")).toBeVisible()
  await expect(page.getByText("Expired").first()).toBeVisible()
  await expect(page.getByText("Review due").first()).toBeVisible()
  await expect(page.getByText("service:checkout").first()).toBeVisible()
  await expect(page.getByText("legacy-risk").first()).toBeVisible()
  await expect(page.getByText("risk-team").first()).toBeVisible()

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-067-governance-rollups-waiver-debt.png"),
  })
})
