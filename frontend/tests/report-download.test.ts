import assert from "node:assert/strict"
import test from "node:test"

import {
  reportDownloadHeaders,
  reportDownloadPath,
  reportDownloadRequest,
  reportDownloadUrl,
} from "../src/workbench/report-download.ts"

test("uses the generated same-origin report download API path", () => {
  assert.equal(
    reportDownloadPath({
      id: "report/../external",
    }),
    "/api/v1/reports/report%2F..%2Fexternal/download",
  )
})

test("does not derive report download targets from absolute metadata URLs", () => {
  const report = {
    download_url: "https://attacker.example/download?token=steal",
    id: "visible-report",
  }

  const request = reportDownloadRequest(report, "local-token")

  assert.equal(request.url, "/api/v1/reports/visible-report/download")
  assert.deepEqual(request.headers, { Authorization: "Bearer local-token" })
})

test("uses the configured API base for generated report download paths", () => {
  assert.equal(
    reportDownloadUrl(
      {
        id: "visible-report",
      },
      "http://localhost:8000/",
    ),
    "http://localhost:8000/api/v1/reports/visible-report/download",
  )
})

test("builds bearer headers only from the local access token input", () => {
  assert.deepEqual(reportDownloadHeaders("local-token"), {
    Authorization: "Bearer local-token",
  })
  assert.equal(reportDownloadHeaders(""), undefined)
})
