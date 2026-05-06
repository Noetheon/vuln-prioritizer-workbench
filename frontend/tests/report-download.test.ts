import assert from "node:assert/strict"
import test from "node:test"

import {
  reportDownloadHeaders,
  reportDownloadPath,
  reportDownloadRequest,
  reportDownloadUrl,
} from "../src/workbench/report-download.ts"

function headerEntries(headers: HeadersInit | undefined) {
  return headers instanceof Headers ? Object.fromEntries(headers) : headers
}

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
  assert.equal(request.credentials, "include")
  assert.deepEqual(headerEntries(request.headers), {
    authorization: "Bearer local-token",
  })
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
  assert.deepEqual(headerEntries(reportDownloadHeaders("local-token")), {
    authorization: "Bearer local-token",
  })
  assert.equal(reportDownloadHeaders(""), undefined)
})
