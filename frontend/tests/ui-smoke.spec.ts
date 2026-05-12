import { expect, test } from "@playwright/test"
import { login } from "./auth-helpers"

test("smoke: dashboard renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/")
  await expect(
    page.getByRole("heading", { name: "Risk Operations", level: 1 }).first(),
  ).toBeVisible()
})

test("smoke: imports renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/imports")
  await expect(
    page.getByRole("heading", { name: "Import Wizard" }),
  ).toBeVisible()
  await expect(page.getByText("Provider and ATT&CK options")).toBeVisible()
  await expect(page.getByLabel("Provider snapshot file")).toBeVisible()
  await expect(page.getByLabel("ATT&CK source")).toBeVisible()
  await page.getByRole("combobox", { name: "Input type" }).click()
  await expect(page.getByRole("option", { name: "CycloneDX SBOM JSON" })).toBeVisible()
  await expect(page.getByRole("option", { name: "Nessus XML" })).toBeVisible()
  await page.keyboard.press("Escape")
})

test("smoke: findings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/findings")
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
})

test("smoke: evidence center renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/reports")
  await expect(
    page.getByRole("heading", { name: "Generate Evidence Artifacts" }),
  ).toBeVisible()
})

test("smoke: providers renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/providers")
  await expect(
    page.getByRole("heading", { name: "Provider sources" }),
  ).toBeVisible()
})

test("smoke: settings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/settings")
  await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible()
  await expect(
    page.getByRole("tab", { name: "Runtime & Providers" }),
  ).toBeVisible()
  await expect(page.getByRole("tab", { name: "Diagnostics" })).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Workspace access" }),
  ).toBeVisible()
})

test("smoke: local workspace indicator does not expose legacy sign out", async ({
  page,
}) => {
  test.setTimeout(30_000)
  await login(page)

  await expect(page.getByLabel("Local workspace status")).toBeVisible()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toHaveCount(0)
  await expect(page.getByText("Account")).toHaveCount(0)
})
