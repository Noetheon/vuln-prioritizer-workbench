import assert from "node:assert/strict"
import test from "node:test"

import {
  configureReportDownloadClient,
  fetchReportDownload,
} from "../src/workbench/report-download.ts"

type DownloadReportClient = Parameters<typeof configureReportDownloadClient>[0]

test.afterEach(() => {
  configureReportDownloadClient(null)
})

test("downloads reports through the generated binary client endpoint", async () => {
  const calls: unknown[] = []
  configureReportDownloadClient((async (parameters, options) => {
    calls.push({ options, parameters })
    return {
      data: new Blob(["report-body"], { type: "text/markdown" }),
      request: new Request("http://localhost/api/v1/reports/visible/download"),
      response: new Response("", {
        headers: {
          "content-disposition": "attachment; filename*=UTF-8''visible.md",
        },
      }),
    }
  }) as DownloadReportClient)

  const artifact = await fetchReportDownload({
    filename: "fallback.md",
    id: "visible",
  })

  assert.equal(artifact.filename, "visible.md")
  assert.equal(await artifact.blob.text(), "report-body")
  assert.deepEqual(calls, [
    {
      options: { parseAs: "blob", responseStyle: "fields" },
      parameters: { report_id: "visible" },
    },
  ])
})

test("falls back to server report filename when content disposition is absent", async () => {
  configureReportDownloadClient((async () => ({
    data: new Blob(["report-body"]),
    request: new Request("http://localhost/api/v1/reports/visible/download"),
    response: new Response(""),
  })) as DownloadReportClient)

  const artifact = await fetchReportDownload({
    filename: "fallback.md",
    id: "visible",
  })

  assert.equal(artifact.filename, "fallback.md")
})

test("does not derive report download targets from absolute metadata URLs", async () => {
  configureReportDownloadClient((async (parameters) => {
    assert.deepEqual(parameters, { report_id: "visible-report" })
    return {
      data: new Blob(["report-body"]),
      request: new Request("http://localhost/api/v1/reports/visible/download"),
      response: new Response(""),
    }
  }) as DownloadReportClient)

  await fetchReportDownload(
    {
      download_url: "https://attacker.example/download?token=steal",
      filename: "visible.md",
      id: "visible-report",
    } as Parameters<typeof fetchReportDownload>[0],
  )
})
