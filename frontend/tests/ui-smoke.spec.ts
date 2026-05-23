import { expect, test } from "@playwright/test"
import { openWorkbench } from "./workbench-runtime-helpers"

test("smoke: dashboard renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/")
  await expect(
    page.getByRole("heading", { name: "Overview", level: 1 }).first(),
  ).toBeVisible()
})

test("smoke: imports renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/imports")
  await expect(
    page.getByRole("heading", { level: 1, name: "Imports" }),
  ).toBeVisible()
  await expect(page.getByRole("link", { name: /New import/ })).toBeVisible()
  await expect(page.getByRole("link", { name: /Supported formats/ })).toBeVisible()
  await expect(page.getByLabel("Evidence file")).toHaveCount(0)

  await page.goto("/imports/new")
  await expect(
    page.getByRole("heading", { name: "New import" }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: "Choose source" })).toBeVisible()
  await expect(
    page.getByRole("button", { name: /CycloneDX SBOM JSON/ }),
  ).toBeVisible()
  await expect(page.getByRole("button", { name: /Nessus XML/ })).toBeVisible()
  await expect(page.getByRole("button", { name: /OSV JSON/ })).toHaveCount(0)

  await page.goto("/imports/formats")
  await expect(
    page.getByRole("heading", { name: "Supported formats" }),
  ).toBeVisible()
  await expect(page.getByLabel("Search formats")).toBeVisible()
  await expect(page.getByRole("button", { name: /CycloneDX SBOM JSON/ })).toBeVisible()
  await expect(page.getByRole("button", { name: /Nessus XML/ })).toBeVisible()
  await expect(page.getByText("OSV JSON")).toHaveCount(0)
})

test("smoke: findings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/findings")
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
})

test("smoke: evidence center renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/reports")
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  await expect(page.getByRole("tab", { name: "Artifacts" })).toHaveAttribute(
    "aria-selected",
    "true",
  )
  await expect(
    page.getByRole("heading", { name: "Recommended artifacts" }),
  ).toBeVisible()
})

test("smoke: providers renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/providers")
  await expect(
    page.getByRole("heading", { level: 1, name: "Data Sources" }),
  ).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Source inventory" }),
  ).toBeVisible()
})

test("smoke: settings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await openWorkbench(page)
  await page.goto("/settings")
  await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible()
  await expect(
    page.getByRole("tab", { name: "Runtime & Providers" }),
  ).toBeVisible()
  await expect(page.getByRole("tab", { name: "Diagnostics" })).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Workspace state" }),
  ).toBeVisible()
})

test("smoke: local workspace indicator does not expose legacy sign out", async ({
  page,
}) => {
  test.setTimeout(30_000)
  await openWorkbench(page)

  await expect(page.getByLabel("Local workspace status")).toBeVisible()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toHaveCount(0)
  await expect(page.getByText("Account")).toHaveCount(0)
})
