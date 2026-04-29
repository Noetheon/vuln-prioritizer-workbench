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
})
