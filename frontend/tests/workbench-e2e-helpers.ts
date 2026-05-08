import { readFileSync } from "node:fs"
import { expect, type Locator, type Page } from "@playwright/test"

export const validCveList = Buffer.from("CVE-2021-44228\nCVE-2024-3094\n")

export const cyclonedxVex = readFileSync(
  "../data/input_fixtures/cyclonedx_vex.json",
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
