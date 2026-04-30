import { readFileSync } from "node:fs"
import { expect, test } from "@playwright/test"

const validCveList = Buffer.from("CVE-2021-44228\nCVE-2024-3094\n")
const trivyReport = readFileSync("../data/input_fixtures/trivy_report.json")
const cyclonedxVex = readFileSync("../data/input_fixtures/cyclonedx_vex.json")
const lowConfidenceAttackMapping = "local_curated_low_confidence_vpw058.yml"
const validOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
    "CVE-2024-3094,build-host-1,xz <img src=x onerror=window.__vpwXss=1>,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform <img src=x onerror=window.__vpwXss=1>,payments <script>window.__vpwXss=1</script>,public",
    "CVE-2024-4577,web-tier,php-cgi,8.3.7,pkg:deb/debian/php-cgi@8.3.7,HIGH,team-web,checkout,internal",
  ].join("\n"),
)
const validAssetContextCsv = Buffer.from(
  [
    "target_kind,target_ref,asset_id,owner,business_service,criticality,exposure,environment",
    "generic,ui-sidecar,ui-sidecar-asset,team-sidecar,inventory-sidecar,high,internal,staging",
  ].join("\n"),
)
const importWizardOpenVex = Buffer.from(
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
const invalidOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component_name,component_version,purl,scanner,fix_version,severity,owner,business_service,exposure",
    "not-a-cve,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,trivy,5.6.1-r2,CRITICAL,team-platform,payments,public",
  ].join("\n"),
)
const cyclonedxVexOccurrenceCsv = Buffer.from(
  [
    "cve_id,asset_ref,component,version,purl,severity",
    "CVE-2023-34362,moveit-service,moveit-transfer,2023.0.0,pkg:pypi/moveit-transfer@2023.0.0,HIGH",
  ].join("\n"),
)
test("template finding detail renders TTP Context tab", async ({ page }) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW TTP Context ${testRunSuffix}`

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
        description: "Playwright TTP Context project",
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
        attack_mapping_file: lowConfidenceAttackMapping,
        attack_source: "local-curated",
        file: {
          buffer: trivyReport,
          mimeType: "application/json",
          name: "trivy.json",
        },
        input_type: "trivy-json",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()

  const findingsResponse = await page.request.get(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers: authHeaders },
  )
  expect(findingsResponse.ok()).toBeTruthy()
  const findingsPayload = (await findingsResponse.json()) as {
    data: Array<{ attack_mapped?: boolean; cve_id: string; id: string }>
  }
  const mapped = findingsPayload.data.find(
    (finding) => finding.cve_id === "CVE-2023-34362",
  )
  const unmapped = findingsPayload.data.find(
    (finding) => finding.cve_id === "CVE-2024-3094",
  )
  expect(mapped?.id).toBeTruthy()
  expect(unmapped?.id).toBeTruthy()

  await page.goto("/")
  const currentProjectSelect = page.getByLabel("Current project")
  await expect(currentProjectSelect).toBeVisible()
  await currentProjectSelect.selectOption(project.id)
  const attackWidget = page.getByRole("region", {
    name: "Top ATT&CK techniques dashboard widget",
  })
  await expect(attackWidget).toContainText("Top ATT&CK Techniques")
  await expect(attackWidget).toContainText("T1190")
  await expect(attackWidget).toContainText("Exploit Public-Facing Application")
  await expect(attackWidget).toContainText("1 finding")
  await expect(attackWidget).toContainText("Low 1")
  await expect(attackWidget).toContainText("Mapped")
  await expect(attackWidget).toContainText("Unmapped")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-059-attack-summary-dashboard.png",
  })

  await page.goto(`/findings/${mapped?.id}`)
  await expect(
    page.getByRole("heading", { name: "CVE-2023-34362" }),
  ).toBeVisible()
  await page.getByRole("tab", { name: "TTP Context" }).click()
  const ttpPanel = page.getByRole("tabpanel", { name: "TTP Context" })
  await expect(ttpPanel).toContainText("ATT&CK threat context")
  await expect(ttpPanel).toContainText("local-curated")
  await expect(ttpPanel).toContainText("Low")
  await expect(ttpPanel).toContainText("Review required")
  await expect(ttpPanel).toContainText("Needs Review")
  await expect(ttpPanel).toContainText("T1190")
  await expect(ttpPanel).toContainText("Exploit Public-Facing Application")
  await expect(ttpPanel).toContainText("Detection coverage")
  await expect(ttpPanel).toContainText("Defensive context only")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-058-ttp-context-tab.png",
  })

  await page.goto(`/findings/${unmapped?.id}`)
  await expect(
    page.getByRole("heading", { name: "CVE-2024-3094" }),
  ).toBeVisible()
  await page.getByRole("tab", { name: "TTP Context" }).click()
  const emptyPanel = page.getByRole("tabpanel", { name: "TTP Context" })
  await expect(emptyPanel).toContainText(
    "No approved ATT&CK mapping is stored for this finding",
  )
  await expect(emptyPanel).toContainText(
    "Workbench does not infer tactics or techniques",
  )
  await expect(emptyPanel).toContainText("Defensive context only")
})
test("template frontend renders CycloneDX VEX occurrence evidence", async ({
  page,
}) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const projectName = `VPW CycloneDX VEX ${testRunSuffix}`

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
        description: "Playwright CycloneDX VEX project",
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
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers: authHeaders },
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
  await expect(occurrencesTable).toContainText("vulnerable_code_not_present")
  await expect(occurrencesTable).toContainText("purl")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-066-cyclonedx-vex-parser.png",
  })
})
test("template frontend covers core Workbench E2E smoke", async ({ page }) => {
  test.setTimeout(60_000)
  const testRunSuffix = Date.now().toString(36)
  const dashboardProjectName = `VPW Dashboard Project ${testRunSuffix}`
  const uiProjectName = `VPW UI Project ${testRunSuffix}`
  const editedUiProjectName = `VPW UI Project Edited ${testRunSuffix}`
  const uiAssetKey = `playwright-asset-${testRunSuffix}`
  const uiAssetName = `Playwright Asset ${testRunSuffix}`
  const editedUiAssetName = `Playwright Asset Edited ${testRunSuffix}`

  await page.goto("/login")

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  await expect(page.getByText("Vuln Prioritizer Workbench")).toBeVisible()
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()

  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByText("Backend adapter online")).toBeVisible()
  await expect(page.getByText("admin@example.com")).toBeVisible()
  const navigation = page.getByRole("navigation", {
    name: "Workbench navigation",
  })
  for (const label of [
    "Dashboard",
    "Projects",
    "Imports",
    "Findings",
    "Assets",
    "Providers",
    "Reports",
    "Settings",
  ]) {
    await expect(navigation.getByRole("link", { name: label })).toBeVisible()
  }
  const legacyMenuLabel = ["It", "ems"].join("")
  await expect(
    navigation.getByRole("link", { name: legacyMenuLabel }),
  ).toHaveCount(0)
  await expect(page.getByText(legacyMenuLabel, { exact: true })).toHaveCount(0)
  await expect(page.getByText("template-backend-adapter")).toBeVisible()
  await expect(page.getByText("disabled")).toBeVisible()
  const providerStatusSection = page.getByRole("region", {
    name: "Provider Status",
  })
  await expect(
    providerStatusSection.getByRole("heading", { name: "Provider Status" }),
  ).toBeVisible()
  await expect(providerStatusSection.getByText("Snapshot mode")).toBeVisible()
  const providerSources = page.getByLabel("Provider sources")
  await expect(providerSources.getByText("NVD", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("EPSS", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("KEV", { exact: true })).toBeVisible()

  const accessToken = await page.evaluate(() =>
    window.localStorage.getItem("access_token"),
  )
  expect(accessToken).toBeTruthy()
  const authHeaders = { Authorization: `Bearer ${accessToken}` }
  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright dashboard summary project",
        name: dashboardProjectName,
      },
      headers: authHeaders,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string; name: string }

  await page.reload()
  const currentProjectSelect = page.getByLabel("Current project")
  await expect(currentProjectSelect).toBeVisible()
  await currentProjectSelect.selectOption(project.id)
  await expect(currentProjectSelect).toHaveValue(project.id)
  await expect(
    page.getByRole("region", { name: "No findings empty state" }),
  ).toContainText(`No findings in ${project.name}`)
  await expect(page.getByLabel("Critical summary card")).toContainText("0")
  await expect(page.getByLabel("Latest Runs summary card")).toContainText(
    "No runs",
  )

  const importResponse = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers: authHeaders,
      multipart: {
        file: {
          buffer: validCveList,
          mimeType: "text/plain",
          name: "dashboard-cves.txt",
        },
        input_type: "cve-list",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()

  await page.reload()
  await currentProjectSelect.selectOption(project.id)
  await expect(currentProjectSelect).toHaveValue(project.id)
  await expect(page.getByLabel("Critical summary card")).toContainText("2")
  await expect(page.getByLabel("High summary card")).toContainText("0")
  await expect(page.getByLabel("KEV summary card")).toContainText(/[1-9]/)
  await expect(page.getByLabel("Latest Runs summary card")).toContainText(
    "succeeded",
  )
  await expect(
    page.getByRole("region", { name: "No findings empty state" }),
  ).toHaveCount(0)
  await expect(page.getByLabel("Project decision summary")).toContainText(
    "Total findings",
  )

  const providerStatusResponse = await page.request.get(
    "http://127.0.0.1:8000/api/v1/providers/status",
    { headers: authHeaders },
  )
  expect(providerStatusResponse.ok()).toBeTruthy()
  const providerStatusPayload = (await providerStatusResponse.json()) as {
    snapshot: {
      content_hash?: string | null
      id?: string | null
      locked_provider_data?: boolean | null
    }
    snapshot_mode: string
    sources?: Array<{ name: string }>
  }
  expect(providerStatusPayload.snapshot_mode).toBe("locked")
  expect(providerStatusPayload.snapshot.content_hash).toBeTruthy()
  expect(providerStatusPayload.snapshot.locked_provider_data).toBe(true)
  expect(providerStatusPayload.sources?.map((source) => source.name)).toEqual(
    expect.arrayContaining(["nvd", "epss", "kev"]),
  )

  await navigation.getByRole("link", { name: "Providers" }).click()
  await expect(page).toHaveURL(/\/providers$/)
  await expect(page.getByRole("heading", { name: "Providers" })).toBeVisible()
  const providerStatusPage = page.getByRole("region", {
    name: "Provider Status page",
  })
  await expect(providerStatusPage).toContainText("Snapshot mode")
  await expect(providerStatusPage).toContainText("Cache age")
  await expect(providerStatusPage).toContainText("Snapshot ID")
  const providerCards = page.getByRole("region", { name: "Provider cards" })
  await expect(providerCards).toContainText("NVD")
  await expect(providerCards).toContainText("EPSS")
  await expect(providerCards).toContainText("KEV")
  await expect(providerStatusPage).toContainText("Provider Snapshot")
  await expect(providerStatusPage).toContainText(
    providerStatusPayload.snapshot.content_hash as string,
  )
  await expect(providerStatusPage).toContainText("Data Quality")
  await expect(providerStatusPage).toContainText("stale")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-045-provider-status.png",
  })

  await navigation.getByRole("link", { name: "Reports" }).click()
  await expect(page).toHaveURL(/\/reports$/)
  await expect(
    page.getByRole("heading", { exact: true, name: "Reports" }),
  ).toBeVisible()
  const reportsPage = page.getByRole("region", {
    name: "Reports workspace",
  })
  await expect(reportsPage).toContainText(
    "Generate and download reports for the selected run",
  )
  await expect(reportsPage).toContainText("VPW-048")
  const reportRunSelect = page.getByLabel("Report analysis run")
  await expect(reportRunSelect).toBeEnabled()
  await expect(reportRunSelect).toHaveValue(/[0-9a-f-]{36}/)
  const reportRunSelection = page.getByRole("region", {
    name: "Report run selection",
  })
  await expect(reportRunSelection).toContainText("succeeded")
  const reportCards = page.getByRole("region", {
    name: "Report export cards",
  })
  await expect(reportCards).toContainText("Markdown Technical Report")
  await expect(reportCards).toContainText("HTML Executive Report")
  await expect(reportCards).toContainText("JSON Findings Export")
  await expect(reportCards).toContainText("CSV Findings Export")
  await expect(reportCards).toContainText("ATT&CK Navigator Layer")
  await expect(reportCards).toContainText("Evidence Bundle")
  const expectedReports = [
    { action: "Generate Markdown", filename: "technical-report.md" },
    { action: "Generate HTML", filename: "executive-report.html" },
    { action: "Export JSON", filename: "analysis-result.v1.json" },
    { action: "Export CSV", filename: "findings.csv" },
    {
      action: "Export Navigator Layer",
      filename: "attack-navigator-layer.json",
    },
    { action: "Build Evidence Bundle", filename: "evidence-bundle.zip" },
  ]
  for (const report of expectedReports) {
    const actionButton = reportCards.getByRole("button", {
      name: report.action,
    })
    await expect(actionButton).toBeEnabled()
    await actionButton.click()
    await expect(reportsPage).toContainText(report.filename)
  }
  const reportHistory = page.getByRole("region", { name: "Reports history" })
  await expect(reportHistory).toContainText("technical-report.md")
  await expect(reportHistory).toContainText("executive-report.html")
  await expect(reportHistory).toContainText("analysis-result.v1.json")
  await expect(reportHistory).toContainText("findings.csv")
  await expect(reportHistory).toContainText("attack-navigator-layer.json")
  await expect(reportHistory).toContainText("evidence-bundle.zip")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-060-attack-navigator-layer.png",
  })
  await reportHistory
    .getByRole("button", { name: "Verify evidence-bundle.zip" })
    .click()
  await expect(reportsPage).toContainText("Evidence bundle verified")
  for (const report of expectedReports) {
    const downloadPromise = page.waitForEvent("download")
    await reportHistory
      .getByRole("button", { name: `Download ${report.filename}` })
      .click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe(report.filename)
  }
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-053-report-downloads.png",
  })

  await navigation.getByRole("link", { name: "Projects" }).click()
  await expect(page).toHaveURL(/\/projects$/)
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible()
  const createProjectForm = page.getByRole("region", {
    name: "Create Project form",
  })
  await expect(createProjectForm).toBeVisible()
  await createProjectForm
    .getByRole("button", { name: "Create Project" })
    .click()
  await expect(page.getByText("Project name is required.")).toBeVisible()
  await createProjectForm.getByLabel("Project name").fill(uiProjectName)
  await createProjectForm
    .getByLabel("Description")
    .fill("Created through the Projects page E2E workflow")
  await createProjectForm
    .getByRole("button", { name: "Create Project" })
    .click()
  await expect(
    page.getByText(`Project ${uiProjectName} created.`),
  ).toBeVisible()
  const projectsList = page.getByRole("region", { name: "Projects list" })
  await expect(projectsList.getByText(uiProjectName)).toBeVisible()
  const projectDetail = page.getByRole("region", { name: "Project detail" })
  await expect(projectDetail).toContainText(uiProjectName)
  await projectDetail.getByRole("button", { name: "Edit" }).click()
  await projectDetail.getByLabel("Edit project name").fill(editedUiProjectName)
  await projectDetail
    .getByLabel("Edit description")
    .fill("Updated through the Projects page E2E workflow")
  await projectDetail.getByRole("button", { name: "Save Project" }).click()
  await expect(
    page.getByText(`Project ${editedUiProjectName} updated.`),
  ).toBeVisible()
  await expect(projectDetail).toContainText(editedUiProjectName)
  await projectDetail.getByLabel("Confirm deletion for this project").check()
  await projectDetail.getByRole("button", { name: "Delete Project" }).click()
  await expect(
    page.getByText(`Project ${editedUiProjectName} deleted.`),
  ).toBeVisible()
  await expect(projectsList.getByText(editedUiProjectName)).toHaveCount(0)

  await navigation.getByRole("link", { name: "Imports" }).click()
  await expect(page).toHaveURL(/\/imports$/)
  await expect(
    page.getByRole("region", { name: "Import wizard" }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Upload security notes" }),
  ).toContainText("asset context uploads")
  await expect(
    page.getByRole("region", { name: "Supported MVP formats" }),
  ).toContainText("trivy-json")
  await page.getByLabel("Import project").selectOption(project.id)
  await page.getByLabel("Input type").selectOption("generic-occurrence-csv")
  const importFileInput = page.locator('input[name="importFile"]')
  await importFileInput.setInputFiles({
    buffer: Buffer.from(
      [
        "cve_id,asset_ref,component,version,purl",
        "CVE-2024-3094,ui-sidecar,xz,5.6.0-r0,pkg:apk/alpine/xz@5.6.0-r0?arch=x86_64",
      ].join("\n"),
    ),
    mimeType: "text/csv",
    name: "import-wizard-occurrences.csv",
  })
  await expect(importFileInput).toHaveJSProperty("files.length", 1)
  const assetContextInput = page.locator('input[name="assetContextFile"]')
  await assetContextInput.setInputFiles({
    buffer: validAssetContextCsv,
    mimeType: "text/csv",
    name: "import-wizard-asset-context.csv",
  })
  await expect(assetContextInput).toHaveJSProperty("files.length", 1)
  const vexInput = page.locator('input[name="vexFile"]')
  await vexInput.setInputFiles({
    buffer: importWizardOpenVex,
    mimeType: "application/json",
    name: "import-wizard-openvex.json",
  })
  await expect(vexInput).toHaveJSProperty("files.length", 1)
  await page.getByRole("button", { name: "Upload Import" }).click()
  await expect(
    page.getByRole("region", { name: "Import result" }),
  ).toContainText("succeeded")
  const importRuns = page.getByRole("region", { name: "Import runs" })
  await expect(importRuns).toContainText("import-wizard-occurrences.csv")
  await expect(importRuns).toContainText("succeeded")
  const runDetail = page.getByRole("region", { name: "Run detail" })
  await expect(runDetail).toContainText("Run Detail")
  await expect(runDetail).toContainText("Created")
  await expect(runDetail).toContainText("Provider snapshot")
  const importWizardFindingsResponse = await page.request.get(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers: authHeaders },
  )
  expect(importWizardFindingsResponse.ok()).toBeTruthy()
  const importWizardFindingsPayload =
    (await importWizardFindingsResponse.json()) as {
      data: Array<{
        cve_id: string
        id: string
        status?: string
        suppressed_by_vex?: boolean
      }>
    }
  const vexSuppressedFinding = importWizardFindingsPayload.data.find(
    (finding) =>
      finding.cve_id === "CVE-2024-3094" && finding.suppressed_by_vex,
  )
  expect(vexSuppressedFinding).toBeTruthy()
  if (!vexSuppressedFinding) {
    throw new Error("Expected VEX-suppressed import wizard finding.")
  }
  expect(vexSuppressedFinding?.suppressed_by_vex).toBe(true)
  expect(vexSuppressedFinding?.status).toBe("suppressed")
  await page.goto(`/findings/${vexSuppressedFinding.id}`)
  await expect(
    page.getByRole("table", { name: "Occurrences table" }),
  ).toContainText("Not Affected")
  await expect(
    page.getByRole("table", { name: "Occurrences table" }),
  ).toContainText("vulnerable_code_not_present")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-065-openvex-status-application.png",
  })

  const occurrenceImport = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers: authHeaders,
      multipart: {
        file: {
          buffer: validOccurrenceCsv,
          mimeType: "text/csv",
          name: "findings-occurrences.csv",
        },
        input_type: "generic-occurrence-csv",
      },
    },
  )
  expect(occurrenceImport.ok()).toBeTruthy()

  await navigation.getByRole("link", { name: "Assets" }).click()
  await expect(page).toHaveURL(/\/assets$/)
  await expect(
    page.getByRole("heading", { exact: true, name: "Assets" }),
  ).toBeVisible()
  const assetsProjectSelect = page.getByLabel("Assets project", {
    exact: true,
  })
  await expect(assetsProjectSelect).toBeVisible()
  await assetsProjectSelect.selectOption(project.id)
  await expect(assetsProjectSelect).toHaveValue(project.id)
  const createAssetForm = page.getByRole("region", {
    name: "Create Asset form",
  })
  await expect(createAssetForm).toBeVisible()
  await createAssetForm.getByRole("button", { name: "Create Asset" }).click()
  await expect(page.getByText("Asset key is required.")).toBeVisible()
  await createAssetForm.getByLabel("Asset key").fill(uiAssetKey)
  await createAssetForm.getByLabel("Asset name").fill(uiAssetName)
  await createAssetForm.getByLabel("Owner").fill("team-assets")
  await createAssetForm.getByLabel("Business service").fill("inventory")
  await createAssetForm.getByLabel("Target ref").fill("svc/inventory")
  await createAssetForm.getByLabel("Criticality").selectOption("critical")
  await createAssetForm.getByLabel("Environment").selectOption("production")
  const exposureSelect = createAssetForm.getByLabel("Exposure")
  await exposureSelect.evaluate((select) => {
    const invalidOption = document.createElement("option")
    invalidOption.value = "public"
    invalidOption.textContent = "Public"
    select.appendChild(invalidOption)
  })
  await exposureSelect.selectOption("public")
  await createAssetForm.getByRole("button", { name: "Create Asset" }).click()
  await expect(
    page.getByText("Exposure must be a supported value."),
  ).toBeVisible()
  await exposureSelect.selectOption("internal")
  await createAssetForm.getByRole("button", { name: "Create Asset" }).click()
  await expect(page.getByText(`Asset ${uiAssetName} created.`)).toBeVisible()
  const assetsTable = page.getByRole("table", { name: "Assets table" })
  await expect(assetsTable).toContainText(uiAssetName)
  await expect(assetsTable).toContainText("Critical")
  await expect(assetsTable).toContainText("Production")
  await expect(assetsTable).toContainText("Internal")
  const manualAssetRow = assetsTable.locator("tbody tr").filter({
    hasText: uiAssetName,
  })
  await manualAssetRow.getByRole("button", { name: "Edit" }).click()
  const assetDetail = page.getByRole("region", { name: "Asset detail" })
  await expect(assetDetail).toContainText(uiAssetName)
  await assetDetail.getByLabel("Edit asset name").fill(editedUiAssetName)
  await assetDetail.getByLabel("Edit criticality").selectOption("high")
  await assetDetail.getByLabel("Edit environment").selectOption("staging")
  await assetDetail.getByLabel("Edit exposure").selectOption("private")
  await assetDetail.getByRole("button", { name: "Save Asset" }).click()
  await expect(
    page.getByText(`Asset ${editedUiAssetName} updated.`),
  ).toBeVisible()
  await expect(assetDetail).toContainText(editedUiAssetName)
  await expect(assetDetail).toContainText("High")
  await expect(assetDetail).toContainText("Staging")
  await expect(assetDetail).toContainText("Private")
  const importedAssetRow = assetsTable.locator("tbody tr").filter({
    hasText: "build-host-1",
  })
  await importedAssetRow.locator(".project-list-item").click()
  await expect(assetDetail).toContainText("build-host-1")
  await assetDetail.getByRole("button", { name: "Edit Asset" }).click()
  await assetDetail.getByLabel("Edit owner").fill("team-platform-updated")
  await assetDetail.getByLabel("Edit business service").fill("payments-runtime")
  await assetDetail.getByLabel("Edit criticality").selectOption("critical")
  await assetDetail.getByLabel("Edit environment").selectOption("production")
  await assetDetail.getByLabel("Edit exposure").selectOption("internet-facing")
  await assetDetail.getByRole("button", { name: "Save Asset" }).click()
  await expect(page.getByText("Asset build-host-1 updated.")).toBeVisible()
  await expect(assetDetail).toContainText("team-platform-updated")
  await expect(assetDetail).toContainText("payments-runtime")
  await expect(assetDetail).toContainText("Re-score needed")
  await expect(importedAssetRow).toContainText("Re-score needed")
  await page.getByLabel("Asset owner filter").fill("team-platform-updated")
  await expect(assetsTable).toContainText("build-host-1")
  await expect(assetsTable).not.toContainText("web-tier")
  await page.getByLabel("Asset service filter").fill("payments-runtime")
  await expect(assetsTable).toContainText("build-host-1")
  await page.getByRole("button", { name: "Clear Filters" }).click()
  await expect(page.getByLabel("Asset owner filter")).toHaveValue("")
  await expect(page.getByLabel("Asset service filter")).toHaveValue("")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-044-assets-page.png",
  })
  const assetFindings = page.getByRole("region", {
    name: "Findings for selected asset",
  })
  await expect(assetFindings).toContainText("Findings for Asset")
  await expect(assetFindings).toContainText("CVE-2024-3094")
  await expect(assetFindings).not.toContainText("CVE-2024-4577")
  await assetFindings.getByRole("link", { name: "Findings" }).click()
  await expect(page).toHaveURL(/\/findings\?assetId=/)
  await expect(
    page.locator('[aria-label="Asset finding filter"]'),
  ).toContainText("build-host-1")
  const filteredFindingsTable = page.getByRole("table", {
    name: "Findings table",
  })
  await expect(filteredFindingsTable).toContainText("CVE-2024-3094")
  await expect(filteredFindingsTable).not.toContainText("CVE-2024-4577")
  await filteredFindingsTable
    .getByRole("link", { name: "CVE-2024-3094" })
    .click()
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}$/)
  const assetFindingDetail = page.getByRole("region", {
    exact: true,
    name: "Finding detail",
  })
  await expect(assetFindingDetail).toContainText("build-host-1")
  await expect(assetFindingDetail).toContainText("team-platform-updated")
  await expect(assetFindingDetail).toContainText("payments-runtime")
  await expect(assetFindingDetail).toContainText("Production")
  await expect(assetFindingDetail).toContainText("Critical")
  await expect(assetFindingDetail).toContainText("Asset Context Rescore Needed")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-044-finding-context.png",
  })
  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings$/)

  await navigation.getByRole("link", { name: "Assets" }).click()
  await assetsProjectSelect.selectOption(project.id)
  const recalculationRow = assetsTable.locator("tbody tr").filter({
    hasText: "build-host-1",
  })
  await recalculationRow.getByRole("button", { name: "Recalculate" }).click()
  await expect(
    page.getByText(/Recalculated \d+ finding\(s\) for build-host-1\./),
  ).toBeVisible()
  await expect(recalculationRow).toContainText("Current")
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-063-asset-recalculate.png",
  })

  await navigation.getByRole("link", { name: "Imports" }).click()
  await expect(page).toHaveURL(/\/imports$/)
  await page.getByLabel("Import project").selectOption(project.id)
  await page.getByLabel("Input type").selectOption("generic-occurrence-csv")
  await page.getByLabel("Import file").setInputFiles({
    buffer: invalidOccurrenceCsv,
    mimeType: "text/csv",
    name: "invalid-occurrences.csv",
  })
  await page.getByRole("button", { name: "Upload Import" }).click()
  await expect(page.getByRole("alert")).toContainText("Import upload failed")
  await expect(
    page.getByRole("region", { exact: true, name: "Parser errors" }),
  ).toContainText("cve_id")
  await expect(importRuns).toContainText("invalid-occurrences.csv")
  await expect(importRuns).toContainText("failed")
  await expect(runDetail).toContainText("Failure Cause")
  await expect(runDetail).toContainText("cve_id")
  await expect(runDetail).toContainText("not-a-cve")
  await runDetail.getByRole("link", { name: "Findings" }).click()
  await expect(page).toHaveURL(/\/findings$/)
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
  const findingsTable = page.getByRole("table", { name: "Findings table" })
  await expect(findingsTable).toBeVisible()
  await expect(findingsTable).toContainText("CVE-2021-44228")
  await expect(findingsTable).toContainText("CVE-2024-3094")
  await expect(findingsTable).toContainText("Priority")
  await expect(findingsTable).toContainText("Last Seen")
  await expect(findingsTable.locator(".severity.critical").first()).toHaveText(
    "Critical",
  )
  await expect(
    findingsTable.locator(".finding-row.tone-critical").first(),
  ).toBeVisible()

  const xzFindingRow = findingsTable
    .locator("tbody tr")
    .filter({ hasText: "build-host-1" })
  await xzFindingRow.getByRole("link", { name: "CVE-2024-3094" }).click()
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}$/)
  const findingDetail = page.getByRole("region", {
    exact: true,
    name: "Finding detail",
  })
  await expect(findingDetail).toBeVisible()
  const detailHeader = page.getByRole("region", {
    name: "Finding detail header",
  })
  await expect(detailHeader).toContainText("CVE-2024-3094")
  await expect(detailHeader).toContainText("Critical")
  await expect(detailHeader).toContainText("Open")
  const findingOverview = page.getByRole("region", {
    name: "Finding overview",
  })
  await expect(findingOverview).toContainText("EPSS")
  await expect(findingOverview).toContainText("CVSS")
  await expect(findingOverview).toContainText("10.0")
  await expect(findingOverview).toContainText("KEV")
  await expect(findingOverview).toContainText("Asset")
  await expect(findingOverview).toContainText("build-host-1")
  const whyPriority = page.getByRole("region", { name: "Why this priority" })
  await expect(whyPriority).toContainText("Recommended action")
  await expect(whyPriority).toContainText(/priority|Critical|CVSS|EPSS|KEV/i)
  const occurrencesTable = page.getByRole("table", {
    name: "Occurrences table",
  })
  await expect(occurrencesTable).toContainText("generic-occurrence-csv")
  await expect(occurrencesTable).toContainText(
    "xz <img src=x onerror=window.__vpwXss=1>",
  )
  await expect(occurrencesTable).toContainText("5.6.0")
  await expect(occurrencesTable).toContainText("build-host-1")
  await expect(occurrencesTable).toContainText("team-platform")
  await expect(occurrencesTable).toContainText("payments")
  await expect(findingDetail).toContainText(
    "team-platform <img src=x onerror=window.__vpwXss=1>",
  )
  await expect(findingDetail).toContainText(
    "payments <script>window.__vpwXss=1</script>",
  )
  await expect(page.locator('img[src="x"]')).toHaveCount(0)
  await expect(
    page.locator("script", { hasText: "window.__vpwXss" }),
  ).toHaveCount(0)
  const xssMarker = await page.evaluate(
    () => (window as Window & { __vpwXss?: number }).__vpwXss ?? null,
  )
  expect(xssMarker).toBeNull()
  const dataQuality = page.getByRole("region", {
    name: "Data Quality Flags",
  })
  await expect(dataQuality).toContainText("Provider data coverage")
  await expect(dataQuality).toContainText(
    /Confidence|snapshot|No data quality/i,
  )
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-047-core-workbench-flow.png",
  })
  await page.screenshot({
    fullPage: true,
    path: "../docs/evidence/vpw-043-finding-detail.png",
  })
  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings$/)
  await expect(findingsTable).toBeVisible()

  await page.getByLabel("Priority filter").selectOption("critical")
  await expect(findingsTable).toContainText("Critical")
  await expect(findingsTable).not.toContainText("Medium")
  await page.getByRole("button", { name: "Clear Filters" }).click()
  await expect(findingsTable).toContainText("CVE-2024-3094")

  await page.getByLabel("Owner service filter").fill("payments")
  await expect(findingsTable).toContainText("team-platform")
  await expect(findingsTable).toContainText("payments")
  await expect(findingsTable).not.toContainText("team-web")
  await page.getByRole("button", { name: "Clear Filters" }).click()

  await page.getByLabel("KEV filter").selectOption("true")
  await expect(findingsTable.locator(".kev-pill.matched").first()).toHaveText(
    "Yes",
  )
  await page.getByRole("button", { name: "Clear Filters" }).click()

  await page.getByLabel("EPSS min filter").fill("0.90")
  await page.getByLabel("CVSS min filter").fill("9.0")
  await expect(findingsTable).toContainText(/CVE-2021-44228|CVE-2024-4577/)
  await page.getByRole("button", { name: "Clear Filters" }).click()

  await page.getByLabel("Sort findings").selectOption("cve")
  await page.getByLabel("Sort direction").selectOption("asc")
  await expect(findingsTable.locator("tbody tr").first()).toContainText(
    "CVE-2021-44228",
  )
  await page.getByLabel("Findings page size").selectOption("1")
  await expect(page.getByText(/1-1 of \d+/)).toBeVisible()
  await page.getByRole("button", { name: "Next" }).click()
  await expect(page.getByText(/2-2 of \d+/)).toBeVisible()
  await page.getByRole("button", { name: "Previous" }).click()
  await expect(page.getByText(/1-1 of \d+/)).toBeVisible()

  await page.getByLabel("Owner service filter").fill("does-not-exist")
  const findingsFilterEmptyState = page.getByRole("region", {
    name: "Findings filter empty state",
  })
  await expect(findingsFilterEmptyState).toContainText(
    "No findings match these filters",
  )
  await findingsFilterEmptyState
    .getByRole("button", { name: "Clear Filters" })
    .click()

  await navigation.getByRole("link", { name: "Settings" }).click()
  await expect(page).toHaveURL(/\/settings$/)
  await expect(
    page.getByRole("heading", { exact: true, name: "Settings" }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "User Settings" }),
  ).toContainText("admin@example.com")

  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
})
