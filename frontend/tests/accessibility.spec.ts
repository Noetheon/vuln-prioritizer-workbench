import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"

async function expectFocusedElementVisible(page: Page) {
  await expect(page.locator(":focus")).toBeVisible()
}

test("login exposes labels, required fields, and keyboard submit", async ({
  page,
}) => {
  await page.goto("/login")

  await expect(page.getByRole("main")).toBeVisible()
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  await expect(page.getByLabel("Email")).toHaveValue("")
  await expect(page.getByLabel("Password")).toHaveValue("")
  await expect(
    page.evaluate(() => window.localStorage.getItem("access_token")),
  ).resolves.toBeNull()
  await expect(page.getByLabel("Email")).toHaveAttribute("required", "")
  await expect(page.getByLabel("Password")).toHaveAttribute("required", "")

  await page.keyboard.press("Tab")
  await expect(page.getByLabel("Email")).toBeFocused()
})

test("authenticated shell exposes landmarks and account controls", async ({
  page,
}) => {
  await login(page)

  await expect(page.getByRole("main")).toBeVisible()
  await expect(
    page.getByRole("navigation", { name: "Workbench navigation" }),
  ).toBeVisible()
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByRole("link", { exact: true, name: "Findings" }),
  ).toBeVisible()

  await page.keyboard.press("Tab")
  await expectFocusedElementVisible(page)
})
