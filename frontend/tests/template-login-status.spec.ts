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
})
