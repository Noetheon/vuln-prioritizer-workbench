import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "on-first-retry",
  },
  webServer: [
    {
      command:
        "cd .. && PYTHONPATH=backend:backend/src python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000",
      reuseExistingServer: true,
      timeout: 120_000,
      url: "http://127.0.0.1:8000/api/v1/utils/health-check/",
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 5173",
      reuseExistingServer: true,
      timeout: 120_000,
      url: "http://127.0.0.1:5173/login",
    },
  ],
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
})
