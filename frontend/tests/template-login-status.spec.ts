import { expect, test } from "@playwright/test"

test("template login reaches authenticated Workbench status shell", async ({
  page,
}) => {
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
  await expect(
    page.getByRole("heading", { name: "Provider Status" }),
  ).toBeVisible()
  await expect(page.getByText("Snapshot mode")).toBeVisible()
  await expect(page.getByText("No snapshot recorded")).toBeVisible()
  const providerSources = page.getByLabel("Provider sources")
  await expect(providerSources.getByText("NVD", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("EPSS", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("KEV", { exact: true })).toBeVisible()

  await navigation.getByRole("link", { name: "Projects" }).click()
  await expect(page).toHaveURL(/\/projects$/)
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible()

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
