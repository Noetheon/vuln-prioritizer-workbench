import assert from "node:assert/strict"
import test from "node:test"

import {
  configureReportDownloadClient,
  fetchReportDownload,
  startReportDownload,
  type StartReportDownloadOptions,
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

test("parses quoted and unquoted content disposition filenames", async () => {
  for (const [header, expected] of [
    ['attachment; filename="quoted report.html"', "quoted report.html"],
    ["attachment; filename=plain-report.csv", "plain-report.csv"],
  ] as const) {
    configureReportDownloadClient((async () => ({
      data: new Blob(["report-body"]),
      request: new Request("http://localhost/api/v1/reports/visible/download"),
      response: new Response("", {
        headers: {
          "content-disposition": header,
        },
      }),
    })) as DownloadReportClient)

    const artifact = await fetchReportDownload({
      filename: "fallback.md",
      id: "visible",
    })

    assert.equal(artifact.filename, expected)
  }
})

test("falls back when filename star is malformed", async () => {
  configureReportDownloadClient((async () => ({
    data: new Blob(["report-body"]),
    request: new Request("http://localhost/api/v1/reports/visible/download"),
    response: new Response("", {
      headers: {
        "content-disposition":
          "attachment; filename*=UTF-8''bad%E0%A4%A; filename=\"fallback.html\"",
      },
    }),
  })) as DownloadReportClient)

  const artifact = await fetchReportDownload({
    filename: "server-fallback.md",
    id: "visible",
  })

  assert.equal(artifact.filename, "fallback.html")
})

test("uses report metadata filename when content disposition has no filename", async () => {
  configureReportDownloadClient((async () => ({
    data: new Blob(["report-body"]),
    request: new Request("http://localhost/api/v1/reports/visible/download"),
    response: new Response("", {
      headers: {
        "content-disposition": "attachment",
      },
    }),
  })) as DownloadReportClient)

  const artifact = await fetchReportDownload({
    filename: "metadata-name.zip",
    id: "visible",
  })

  assert.equal(artifact.filename, "metadata-name.zip")
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

  await fetchReportDownload({
    download_url: "https://attacker.example/download?token=steal",
    filename: "visible.md",
    id: "visible-report",
  } as Parameters<typeof fetchReportDownload>[0])
})

test("delays report object URL revocation until after download click returns", () => {
  const events: string[] = []
  const timers: Array<() => void> = []
  const anchor = {
    download: "",
    href: "",
    click() {
      events.push(`click:${anchor.href}:${anchor.download}`)
    },
    remove() {
      events.push("remove")
    },
  }
  const documentStub: StartReportDownloadOptions["document"] = {
    body: {
      append(node: HTMLElement) {
        assert.equal(node, anchor)
        events.push("append")
      },
    },
    createElement(tagName: string) {
      assert.equal(tagName, "a")
      return anchor as unknown as HTMLAnchorElement
    },
  }
  const urlApi: StartReportDownloadOptions["urlApi"] = {
    createObjectURL(blob: Blob) {
      assert.equal(blob.type, "text/markdown")
      events.push("create")
      return "blob:visible"
    },
    revokeObjectURL(objectUrl: string) {
      events.push(`revoke:${objectUrl}`)
    },
  }

  startReportDownload(
    {
      blob: new Blob(["report-body"], { type: "text/markdown" }),
      filename: "visible.md",
    },
    {
      document: documentStub,
      revokeDelayMs: 25,
      setTimeout(handler, delayMs) {
        events.push(`timer:${delayMs}`)
        timers.push(handler)
      },
      urlApi,
    },
  )

  assert.deepEqual(events, [
    "create",
    "append",
    "click:blob:visible:visible.md",
    "remove",
    "timer:25",
  ])
  assert.equal(timers.length, 1)

  timers[0]()

  assert.deepEqual(events, [
    "create",
    "append",
    "click:blob:visible:visible.md",
    "remove",
    "timer:25",
    "revoke:blob:visible",
  ])
})

test("cleans up and revokes object URL when report download click throws", () => {
  const events: string[] = []
  const timers: Array<() => void> = []
  const anchor = {
    download: "",
    href: "",
    click() {
      events.push("click")
      throw new Error("browser refused download")
    },
    remove() {
      events.push("remove")
    },
  }
  const documentStub: StartReportDownloadOptions["document"] = {
    body: {
      append(node: HTMLElement) {
        assert.equal(node, anchor)
        events.push("append")
      },
    },
    createElement(tagName: string) {
      assert.equal(tagName, "a")
      return anchor as unknown as HTMLAnchorElement
    },
  }
  const urlApi: StartReportDownloadOptions["urlApi"] = {
    createObjectURL() {
      events.push("create")
      return "blob:visible"
    },
    revokeObjectURL(objectUrl: string) {
      events.push(`revoke:${objectUrl}`)
    },
  }

  assert.throws(
    () =>
      startReportDownload(
        {
          blob: new Blob(["report-body"]),
          filename: "visible.md",
        },
        {
          document: documentStub,
          revokeDelayMs: 10,
          setTimeout(handler, delayMs) {
            events.push(`timer:${delayMs}`)
            timers.push(handler)
          },
          urlApi,
        },
      ),
    /browser refused download/,
  )

  assert.deepEqual(events, ["create", "append", "click", "remove", "timer:10"])
  assert.equal(timers.length, 1)
  timers[0]()
  assert.deepEqual(events, [
    "create",
    "append",
    "click",
    "remove",
    "timer:10",
    "revoke:blob:visible",
  ])
})
