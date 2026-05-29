import { readFileSync } from "node:fs"
import { expect, type Locator, type Page } from "@playwright/test"

export const validCveList = Buffer.from("CVE-2021-44228\nCVE-2024-3094\n")

export const cyclonedxVex = readFileSync(
  new URL("../../data/input_fixtures/cyclonedx_vex.json", import.meta.url),
)

export const validOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
    "CVE-2024-3094,build-host-1,xz <img src=x onerror=window.__vpwXss=1>,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform <img src=x onerror=window.__vpwXss=1>,payments <script>window.__vpwXss=1</script>,public",
    "CVE-2024-4577,web-tier,php-cgi,8.3.7,pkg:deb/debian/php-cgi@8.3.7,HIGH,team-web,checkout,internal",
  ].join("\n"),
)

export const validAssetContextCsv = Buffer.from(
  [
    "target_kind,target_ref,asset_id,owner,business_service,criticality,exposure,environment",
    "generic,ui-sidecar,ui-sidecar-asset,team-sidecar,inventory-sidecar,high,internal,staging",
  ].join("\n"),
)

export const importWizardOpenVex = Buffer.from(
  JSON.stringify({
    statements: [
      {
        justification: "vulnerable_code_not_present",
        products: [
          {
            identifiers: {
              purl: "pkg:apk/alpine/xz@5.6.0-r0?arch=x86_64",
            },
          },
        ],
        status: "not_affected",
        vulnerability: { name: "CVE-2024-3094" },
      },
    ],
  }),
)

export const invalidOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component_name,component_version,purl,scanner,fix_version,severity,owner,business_service,exposure",
    "not-a-cve,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,trivy,5.6.1-r2,CRITICAL,team-platform,payments,public",
  ].join("\n"),
)

export const cyclonedxVexOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity",
    "CVE-2023-34362,moveit-service,moveit-transfer,2023.0.0,pkg:pypi/moveit-transfer@2023.0.0,HIGH",
  ].join("\n"),
)

export async function selectRadixOption(
  page: Page,
  trigger: Locator,
  optionName: string | RegExp,
) {
  await expect(trigger).toBeVisible()
  await expect(trigger).toBeEnabled()
  if (typeof optionName === "string") {
    let lastError: unknown
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await trigger.click()
      const option = page.getByRole("option", { exact: true, name: optionName })
      try {
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
      } catch (error) {
        lastError = error
        await page.keyboard.press("Escape")
        await page.waitForTimeout(500)
      }
    }
    throw lastError
  }
  await trigger.click()
  const option = page.getByRole("option", { name: optionName })
  try {
    await option.scrollIntoViewIfNeeded({ timeout: 1000 })
    await option.click({ timeout: 3000 })
  } catch {
    await option.click({ force: true })
  }
}

export async function selectRadixOptionByLabel(
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

export async function selectDashboardProject(page: Page, projectName: string) {
  const projectTrigger = page.getByRole("combobox").first()
  await selectRadixOption(page, projectTrigger, projectName)
  await expect(projectTrigger).toContainText(projectName)
}

type WorkflowBackedRun = {
  diagnostics?: unknown
  error_message?: string | null
  id: string
  status: string
  workflow?: {
    diagnostics?: unknown
    error_message?: string | null
    status?: string | null
  } | null
}

export async function waitForRunSucceeded(
  page: Page,
  runId: string,
  options: {
    apiBaseUrl?: string
    headers?: Record<string, string>
    timeoutMs?: number
  } = {},
): Promise<WorkflowBackedRun> {
  const startedAt = Date.now()
  const timeoutMs = options.timeoutMs ?? 60_000
  const apiBaseUrl = (options.apiBaseUrl ?? "").replace(/\/+$/, "")
  let lastRun: WorkflowBackedRun | undefined

  while (Date.now() - startedAt < timeoutMs) {
    const response = await page.request.get(`${apiBaseUrl}/api/v1/runs/${runId}`, {
      headers: options.headers,
    })
    if (response.ok()) {
      const run = (await response.json()) as WorkflowBackedRun
      lastRun = run
      const workflowStatus = run.workflow?.status ?? null
      const status = workflowStatus ?? run.status
      if (status === "succeeded" || status === "completed") {
        return run
      }
      if (
        status === "failed" ||
        status === "cancelled" ||
        run.status === "failed" ||
        run.status === "cancelled"
      ) {
        throw new Error(
          `Run ${runId} finished as ${status}: ${JSON.stringify(
            run.workflow?.diagnostics ?? run.diagnostics ?? {},
          )}`,
        )
      }
    }
    await page.waitForTimeout(250)
  }

  throw new Error(
    `Run ${runId} did not finish within ${timeoutMs}ms; last status ${JSON.stringify(
      lastRun?.workflow?.status ?? lastRun?.status ?? null,
    )}`,
  )
}
