import { expect, test } from "@playwright/test"
import {
  backendBaseUrl,
  localApiHeaders,
  openWorkbench,
} from "./workbench-runtime-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  importWizardOpenVex,
  invalidOccurrenceCsv,
  selectDashboardProject,
  selectRadixOption,
  selectRadixOptionByLabel,
  validAssetContextCsv,
  validCveList,
  validOccurrenceCsv,
} from "./workbench-e2e-helpers"
test("workbench frontend covers core Workbench E2E smoke", async ({ page }) => {
  test.setTimeout(180_000)
  const testRunSuffix = Date.now().toString(36)
  const dashboardProjectName = `VPW Dashboard Project ${testRunSuffix}`
  const uiProjectName = `VPW UI Project ${testRunSuffix}`
  const editedUiProjectName = `VPW UI Project Edited ${testRunSuffix}`
  const uiAssetKey = `playwright-asset-${testRunSuffix}`
  const uiAssetName = `Playwright Asset ${testRunSuffix}`
  const editedUiAssetName = `Playwright Asset Edited ${testRunSuffix}`

  await page.goto("/")
  await expect(
    page.getByRole("heading", { exact: true, name: "Risk Operations" }),
  ).toBeVisible()
  await expect(page.getByLabel("Email")).toHaveCount(0)
  await expect(page.getByLabel("Password")).toHaveCount(0)

  await openWorkbench(page)
  await expect(page).toHaveURL(/\/(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { exact: true, name: "Risk Operations" }),
  ).toBeVisible()
  await expect(page.getByLabel("Local workspace status")).toBeVisible()
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
  await expect(navigation.getByRole("link", { name: "Items" })).toHaveCount(0)
  await expect(page.getByText("Items", { exact: true })).toHaveCount(0)
  await expect(
    page.getByRole("link", { name: "Import findings" }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole("link", { name: "Generate evidence" }).first(),
  ).toBeVisible()

  const headers = localApiHeaders()
  const projectResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/`,
    {
      data: {
        description: "Playwright dashboard summary project",
        name: dashboardProjectName,
      },
      headers,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string; name: string }

  await page.reload()
  await selectDashboardProject(page, project.name)
  await expect(page.getByLabel("No remediation queue items")).toContainText(
    "No findings",
  )
  await expect(page.getByLabel("Critical Open summary card")).toContainText("0")
  await expect(page.getByLabel("Latest Analysis summary card")).toContainText(
    "No runs",
  )

  const importResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/${project.id}/imports`,
    {
      headers,
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
  await selectDashboardProject(page, project.name)
  await expect(page.getByLabel("KEV Exposed summary card")).toContainText(
    /[1-9]/,
  )
  await expect(page.getByLabel("Latest Analysis summary card")).toContainText(
    "succeeded",
  )
  await expect(page.getByText("Top Remediation Queue")).toBeVisible()
  await expect(
    page.getByRole("link", { name: "CVE-2024-3094" }).first(),
  ).toBeVisible()

  const providerStatusResponse = await page.request.get(
    `${backendBaseUrl}/api/v1/providers/status`,
    { headers },
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
  await expect(page).toHaveURL(/\/providers(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Providers" }),
  ).toBeVisible()
  await expect(page.getByText("Snapshot mode").first()).toBeVisible()
  await expect(page.getByText("Cache age").first()).toBeVisible()
  await expect(page.getByText("Provider sources").first()).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Provider sources" }),
  ).toContainText("NVD")
  await expect(
    page.getByRole("table", { name: "Provider sources" }),
  ).toContainText("EPSS")
  await expect(
    page.getByRole("table", { name: "Provider sources" }),
  ).toContainText("KEV")
  await expect(page.getByText("Provider Snapshot").first()).toBeVisible()
  await expect(page.getByText("Recorded snapshot").first()).toBeVisible()
  await expect(page.getByText("Snapshot ID").first()).toBeVisible()
  await expect(page.getByText("Data quality").first()).toBeVisible()
  await expect(
    page.getByText("Provider data quality notes").first(),
  ).toBeVisible()
  await expect(page.getByText("stale").first()).toBeVisible()
  await expect(
    page
      .getByText(providerStatusPayload.snapshot.content_hash as string)
      .first(),
  ).toBeVisible()
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-045-provider-status.png"),
  })

  await navigation.getByRole("link", { name: "Reports" }).click()
  await expect(page).toHaveURL(/\/reports(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  await expect(
    page.getByText(
      "Generate audit-ready vulnerability evidence, executive summaries, and technical exports.",
    ),
  ).toBeVisible()
  await expect(
    page.getByRole("combobox", { name: "Select analysis run" }),
  ).toBeVisible()
  await expect(page.getByText("Ready for generation")).toBeVisible()
  await expect(page.getByText("Generate Evidence Artifacts")).toBeVisible()
  await expect(page.getByText("Markdown Technical Report")).toBeVisible()
  await expect(page.getByText("Executive HTML Report")).toBeVisible()
  await expect(page.getByText("JSON Findings Export")).toBeVisible()
  await expect(page.getByText("CSV Findings Export")).toBeVisible()
  await expect(page.getByText("ATT&CK Navigator Layer")).toBeVisible()
  await expect(page.getByText("SARIF Export")).toBeVisible()
  await expect(page.getByText("Evidence ZIP Bundle")).toBeVisible()
  const expectedReports = [
    { action: "Generate Markdown", filename: "technical-report.md" },
    { action: "Generate HTML", filename: "executive-report.html" },
    { action: "Export JSON", filename: "analysis-result.v1.json" },
    { action: "Export CSV", filename: "findings.csv" },
    { action: "Export Navigator", filename: "attack-navigator-layer.json" },
    { action: "Export SARIF", filename: "results.sarif" },
    { action: "Build Bundle", filename: "evidence-bundle.zip" },
  ]
  for (const report of expectedReports) {
    const actionButton = page.getByRole("button", {
      name: report.action,
    })
    await expect(actionButton).toBeEnabled()
    await actionButton.click()
    await expect(page.getByText(report.filename).first()).toBeVisible()
  }
  const reportHistory = page.getByRole("table", { name: "Report history list" })
  await expect(reportHistory).toContainText("technical-report.md")
  await expect(reportHistory).toContainText("executive-report.html")
  await expect(reportHistory).toContainText("analysis-result.v1.json")
  await expect(reportHistory).toContainText("findings.csv")
  await expect(reportHistory).toContainText("attack-navigator-layer.json")
  await expect(reportHistory).toContainText("results.sarif")
  await expect(reportHistory).toContainText("evidence-bundle.zip")
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-060-attack-navigator-layer.png"),
  })
  await reportHistory
    .getByRole("button", { name: "Verify evidence-bundle.zip" })
    .click()
  await expect(page.getByText("Evidence bundle verified")).toBeVisible()
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
    path: evidenceScreenshotPath("vpw-053-report-downloads.png"),
  })

  await navigation.getByRole("link", { name: "Projects" }).click()
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Projects" }),
  ).toBeVisible()
  await expect(page.getByText("Create Project").first()).toBeVisible()
  await page.getByRole("button", { name: "Create project" }).click()
  await expect(page.getByText("Project name is required.")).toBeVisible()
  await page.getByLabel("Project name").fill(uiProjectName)
  await page
    .getByLabel("Description")
    .fill("Created through the Projects page E2E workflow")
  await page.getByRole("button", { name: "Create project" }).click()
  await expect(
    page.getByText(`Project ${uiProjectName} created.`),
  ).toBeVisible()
  const projectsTable = page.getByRole("table", { name: "Projects" })
  await expect(projectsTable).toContainText(uiProjectName)
  await expect(
    page.getByRole("heading", { name: "Active Project" }),
  ).toBeVisible()
  await expect(page.getByText(uiProjectName).first()).toBeVisible()
  await page.getByRole("button", { name: "Edit" }).click()
  await page.getByLabel("Edit project name").fill(editedUiProjectName)
  await page
    .getByLabel("Edit description")
    .fill("Updated through the Projects page E2E workflow")
  await page.getByRole("button", { name: "Save project" }).click()
  await expect(
    page.getByText(`Project ${editedUiProjectName} updated.`),
  ).toBeVisible()
  await expect(projectsTable).toContainText(editedUiProjectName)
  await expect(
    page.getByRole("heading", { name: editedUiProjectName }),
  ).toBeVisible()
  await page.getByLabel(/Confirm deletion for this project/).check()
  await page.getByRole("button", { name: "Delete project" }).click()
  await expect(
    page.getByText(`Project ${editedUiProjectName} deleted.`),
  ).toBeVisible()
  await expect(projectsTable.getByText(editedUiProjectName)).toHaveCount(0)

  await navigation.getByRole("link", { name: "Imports" }).click()
  await expect(page).toHaveURL(/\/imports(?:\?.*)?$/)
  await page.reload()
  await expect(page).toHaveURL(/\/imports(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { name: "Import Wizard" }),
  ).toBeVisible()
  await expect(page.getByText("Upload Security Notes")).toBeVisible()
  await expect(page.getByText("Files are parsed locally")).toBeVisible()
  await expect(page.getByText("Supported Input Formats")).toBeVisible()
  await expect(page.getByRole("button", { name: /^Trivy JSON/ })).toBeVisible()
  await selectRadixOptionByLabel(page, page, "Import project", project.name)
  await selectRadixOptionByLabel(
    page,
    page,
    "Input type",
    "Generic occurrence CSV",
  )
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
  const assetContextInput = page.locator('input[name="assetContextFile"]')
  await assetContextInput.setInputFiles({
    buffer: validAssetContextCsv,
    mimeType: "text/csv",
    name: "import-wizard-asset-context.csv",
  })
  const vexInput = page.locator('input[name="vexFile"]')
  await vexInput.setInputFiles({
    buffer: importWizardOpenVex,
    mimeType: "application/json",
    name: "import-wizard-openvex.json",
  })
  await page.getByRole("button", { name: "Upload Import" }).click()
  await page.waitForTimeout(1000)
  const importWizardFindingsResponse = await page.request.get(
    `${backendBaseUrl}/api/v1/projects/${project.id}/findings/?sort=cve`,
    { headers },
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
  ).not.toContainText("vulnerable_code_not_present")
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-065-openvex-status-application.png"),
  })

  const occurrenceImport = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/${project.id}/imports`,
    {
      headers,
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
  await expect(page).toHaveURL(/\/assets(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Assets" }),
  ).toBeVisible()
  const assetsProjectSelect = page.getByLabel("Assets project", {
    exact: true,
  })
  await expect(assetsProjectSelect).toBeVisible()
  await selectRadixOption(page, assetsProjectSelect, project.name)
  await expect(assetsProjectSelect).toContainText(project.name)
  const createAssetForm = page.getByRole("form", {
    name: "Create Asset form fields",
  })
  await expect(createAssetForm).toBeVisible()
  await createAssetForm.getByRole("button", { name: "Create Asset" }).click()
  await expect(page.getByText("Asset key is required.")).toBeVisible()
  await createAssetForm.getByLabel("Asset key").fill(uiAssetKey)
  await createAssetForm.getByLabel("Asset name").fill(uiAssetName)
  await createAssetForm.getByLabel("Owner").fill("team-assets")
  await createAssetForm.getByLabel("Business service").fill("inventory")
  await createAssetForm.getByLabel("Target ref").fill("svc/inventory")
  await selectRadixOptionByLabel(
    page,
    createAssetForm,
    "Criticality",
    "Critical",
  )
  await selectRadixOptionByLabel(
    page,
    createAssetForm,
    "Environment",
    "Production",
  )
  const exposureSelect = createAssetForm.getByLabel("Exposure")
  await exposureSelect.click()
  await expect(
    page.getByRole("option", { exact: true, name: "Public" }),
  ).toHaveCount(0)
  await page.getByRole("option", { exact: true, name: "Internal" }).click()
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
  const assetDetail = page
  await expect(page.getByText(uiAssetName).first()).toBeVisible()
  await assetDetail.getByLabel("Edit asset name").fill(editedUiAssetName)
  await selectRadixOptionByLabel(page, assetDetail, "Edit criticality", "High")
  await selectRadixOptionByLabel(
    page,
    assetDetail,
    "Edit environment",
    "Staging",
  )
  await selectRadixOptionByLabel(page, assetDetail, "Edit exposure", "Private")
  await assetDetail.getByRole("button", { name: "Save Asset" }).click()
  await expect(
    page.getByText(`Asset ${editedUiAssetName} updated.`),
  ).toBeVisible()
  await expect(assetsTable).toContainText(editedUiAssetName)
  await expect(assetsTable).toContainText("High")
  await expect(assetsTable).toContainText("Staging")
  await expect(assetsTable).toContainText("Private")
  const importedAssetRow = assetsTable.locator("tbody tr").filter({
    hasText: "build-host-1",
  })
  await importedAssetRow.getByRole("button", { name: "Edit" }).click()
  await expect(page.getByText("build-host-1").first()).toBeVisible()
  await assetDetail.getByLabel("Edit owner").fill("team-platform-updated")
  await assetDetail.getByLabel("Edit business service").fill("payments-runtime")
  await selectRadixOptionByLabel(
    page,
    assetDetail,
    "Edit criticality",
    "Critical",
  )
  await selectRadixOptionByLabel(
    page,
    assetDetail,
    "Edit environment",
    "Production",
  )
  await selectRadixOptionByLabel(
    page,
    assetDetail,
    "Edit exposure",
    "Internet Facing",
  )
  await assetDetail.getByRole("button", { name: "Save Asset" }).click()
  await expect(page.getByText("Asset build-host-1 updated.")).toBeVisible()
  await expect(page.getByText("team-platform-updated").first()).toBeVisible()
  await expect(page.getByText("payments-runtime").first()).toBeVisible()
  await expect(page.getByText("Re-score needed").first()).toBeVisible()
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
    path: evidenceScreenshotPath("vpw-044-assets-page.png"),
  })
  const assetFindings = page.getByRole("table", {
    name: "Asset findings table",
  })
  await expect(assetFindings).toContainText("CVE-2024-3094")
  await expect(assetFindings).not.toContainText("CVE-2024-4577")
  await page.getByRole("link", { name: "View findings" }).nth(1).click()
  await expect(page).toHaveURL(/\/findings\?.*assetId=/)
  await expect(
    page.getByRole("button", { name: "Clear asset filter" }),
  ).toBeVisible()
  await expect(page.getByText("build-host-1").first()).toBeVisible()
  const filteredFindingsTable = page.getByRole("table", {
    name: "Findings remediation queue",
  })
  await expect(filteredFindingsTable).toContainText("CVE-2024-3094")
  await expect(filteredFindingsTable).not.toContainText("CVE-2024-4577")
  await filteredFindingsTable
    .getByRole("link", { name: "CVE-2024-3094" })
    .click()
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}(?:\?.*)?$/)
  const assetFindingDetail = page.getByRole("region", {
    name: "Finding priority decision",
  })
  await expect(assetFindingDetail).toContainText("build-host-1")
  await expect(assetFindingDetail).toContainText("team-platform-updated")
  await expect(assetFindingDetail).toContainText("payments-runtime")
  await expect(assetFindingDetail).toContainText("Production")
  await expect(assetFindingDetail).toContainText("Critical")
  await expect(assetFindingDetail).toContainText("Asset Context Rescore Needed")
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-044-finding-context.png"),
  })
  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings(?:\?.*)?$/)

  await navigation.getByRole("link", { name: "Assets" }).click()
  await selectRadixOption(page, assetsProjectSelect, project.name)
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
    path: evidenceScreenshotPath("vpw-063-asset-recalculate.png"),
  })

  await navigation.getByRole("link", { name: "Imports" }).click()
  await expect(page).toHaveURL(/\/imports(?:\?.*)?$/)
  await selectRadixOptionByLabel(page, page, "Import project", project.name)
  await selectRadixOptionByLabel(
    page,
    page,
    "Input type",
    "Generic occurrence CSV",
  )
  await page.getByLabel("Import file").setInputFiles({
    buffer: invalidOccurrenceCsv,
    mimeType: "text/csv",
    name: "invalid-occurrences.csv",
  })
  await page.getByRole("button", { name: "Upload Import" }).click()
  await expect(
    page.getByRole("alert").filter({ hasText: "Import upload failed" }),
  ).toContainText("Import upload failed")
  const importRuns = page
    .getByRole("table", { name: "Recent import runs" })
    .first()
  await expect(
    page.getByRole("table", { name: "Parser errors" }).first(),
  ).toContainText("cve_id")
  await expect(importRuns).toContainText("invalid-occurrences.csv")
  await expect(importRuns).toContainText("failed")
  await expect(page.getByText("Failure Cause").first()).toBeVisible()
  await expect(page.getByText("not-a-cve").first()).toBeVisible()
  await navigation.getByRole("link", { name: "Findings" }).click()
  await expect(page).toHaveURL(/\/findings(?:\?.*)?$/)
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
  const findingsTable = page.getByRole("table", {
    name: "Findings remediation queue",
  })
  await expect(findingsTable).toBeVisible()
  await expect(findingsTable).toContainText("CVE-2021-44228")
  await expect(findingsTable).toContainText("CVE-2024-3094")
  await expect(findingsTable).toContainText("Priority")
  await expect(findingsTable).toContainText("Signals")
  await expect(findingsTable).toContainText("Critical")

  const xzFindingRow = findingsTable
    .locator("tbody tr")
    .filter({ hasText: "build-host-1" })
  await xzFindingRow.getByRole("link", { name: "CVE-2024-3094" }).click()
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}(?:\?.*)?$/)
  const findingDetail = page.getByRole("region", {
    name: "Finding priority decision",
  })
  await expect(findingDetail).toBeVisible()
  const detailHeader = page.getByRole("region", {
    name: "Finding decision hero",
  })
  await expect(detailHeader).toContainText("CVE-2024-3094")
  await expect(detailHeader).toContainText("Critical")
  await expect(detailHeader).toContainText("Open")
  const findingOverview = page.getByLabel("Risk indicators")
  await expect(findingOverview).toContainText("EPSS")
  await expect(findingOverview).toContainText("CVSS")
  await expect(findingOverview).toContainText("10.0")
  const whyPriority = page.getByRole("region", { name: "Risk to decision" })
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
  const dataQuality = page.getByLabel("Data quality notes")
  await expect(dataQuality).toContainText("Provider data")
  await expect(dataQuality).toContainText(
    /Confidence|snapshot|No data quality/i,
  )
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-047-core-workbench-flow.png"),
  })
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("vpw-043-finding-detail.png"),
  })
  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings(?:\?.*)?$/)
  await expect(findingsTable).toBeVisible()
  const findingsFilters = page.getByRole("region", { name: "Findings filters" })

  await selectRadixOptionByLabel(page, findingsFilters, "Priority", "Critical")
  await expect(findingsTable).toContainText("Critical")
  await expect(findingsTable).not.toContainText("Medium")
  await page.getByRole("button", { name: "Reset" }).click()
  await expect(page).not.toHaveURL(/priority=critical/)
  await expect(page).toHaveURL(/projectId=/)
  await expect(page.getByRole("button", { name: "Reset" })).toBeDisabled()
  await expect(findingsTable).toContainText("CVE-2024-3094")

  const ownerServiceInput = page.getByLabel("Owner / Service")
  await ownerServiceInput.fill("payments")
  await expect(ownerServiceInput).toHaveValue("payments")
  await expect(page).toHaveURL(/ownerService=payments/)
  await expect(findingsTable).toContainText("team-platform")
  await expect(findingsTable).toContainText("payments")
  await expect(findingsTable).not.toContainText("team-web")
  await page.getByRole("button", { name: "Reset" }).click()

  await findingsFilters.getByRole("button", { name: /Signals/ }).click()
  const kevFilter = findingsFilters.getByRole("combobox", {
    exact: true,
    name: "KEV",
  })
  const kevUrl = new URL(page.url())
  kevUrl.searchParams.set("kev", "true")
  await page.goto(`${kevUrl.pathname}${kevUrl.search}`)
  await expect(page).toHaveURL(/kev=true/)
  await expect(kevFilter).toContainText("KEV")
  await expect(findingsTable).toContainText("KEV")
  await expect(page.getByRole("button", { name: "Reset" })).toBeEnabled()
  await page.getByRole("button", { name: "Reset" }).click()

  const epssMinInput = page.getByLabel("EPSS min")
  if (!(await epssMinInput.isVisible())) {
    await findingsFilters.getByRole("button", { name: /Signals/ }).click()
  }
  const scoreUrl = new URL(page.url())
  scoreUrl.searchParams.set("epssMin", "0.90")
  scoreUrl.searchParams.set("cvssMin", "9.0")
  await page.goto(`${scoreUrl.pathname}${scoreUrl.search}`)
  await expect(page).toHaveURL(/epssMin=0\.90/)
  await expect(page).toHaveURL(/cvssMin=9\.0/)
  await expect(epssMinInput).toHaveValue("0.90")
  await expect(page.getByLabel("CVSS min")).toHaveValue("9.0")
  await expect(findingsTable).toContainText(/CVE-2021-44228|CVE-2024-4577/)
  await expect(page.getByRole("button", { name: "Reset" })).toBeEnabled()
  await page.getByRole("button", { name: "Reset" }).click()

  await findingsTable.getByRole("button", { name: /Sort by CVE/ }).click()
  await expect(findingsTable.locator("tbody tr").first()).toContainText(
    "CVE-2021-44228",
  )
  await page.getByLabel("Owner / Service").fill("does-not-exist")
  const findingsFilterEmptyState = page.getByLabel("No filter matches")
  await expect(findingsFilterEmptyState).toContainText(
    "No findings match these filters",
  )
  await findingsFilterEmptyState
    .getByRole("button", { name: "Clear filters" })
    .click()

  await navigation.getByRole("link", { name: "Settings" }).click()
  await expect(page).toHaveURL(/\/settings(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Settings" }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Workspace settings" }),
  ).toContainText("Local workspace")

  await expect(page.getByLabel("Local workspace status")).toBeVisible()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toHaveCount(0)
})
