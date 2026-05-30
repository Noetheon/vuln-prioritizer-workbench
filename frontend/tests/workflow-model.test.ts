import assert from "node:assert/strict"
import test from "node:test"

import {
  dashboardSignalCountsFromApi,
  emptyDashboardSignalCounts,
  emptyFindingQueryPage,
  providerStatusNeedsPolling,
  readAllPages,
  readProjectSummariesWithLimit,
  reportsNeedPolling,
  runDetailNeedsPolling,
} from "../src/workbench/workbench-query-model.ts"
import {
  workflowNeedsPolling,
  workflowIsTerminal,
  workflowProgressLabel,
  workflowStageLabel,
  workflowSummaryLabel,
} from "../src/workbench/workflow-model.ts"
import {
  subscribeWorkflowUpdates,
  workflowStreamUrl,
} from "../src/workbench/workflow-stream.ts"

const runningWorkflow = {
  current_stage: "parse_upload",
  progress_current: 2,
  progress_total: 6,
  status: "running",
} as never

const succeededWorkflow = {
  current_stage: "succeeded",
  progress_current: 6,
  progress_total: 6,
  status: "succeeded",
} as never

test("workflow model formats durable workflow state", () => {
  assert.equal(workflowNeedsPolling(runningWorkflow), true)
  assert.equal(workflowIsTerminal(runningWorkflow), false)
  assert.equal(workflowIsTerminal(succeededWorkflow), true)
  assert.equal(workflowNeedsPolling(succeededWorkflow), false)
  assert.equal(workflowStageLabel(runningWorkflow), "parse upload")
  assert.equal(workflowProgressLabel(runningWorkflow), "2/6")
  assert.equal(
    workflowProgressLabel({ status: "running", progress_total: null } as never),
    "running",
  )
  assert.equal(workflowSummaryLabel(runningWorkflow), "running · parse upload · 2/6")
  assert.equal(workflowSummaryLabel(null), "Workflow not recorded")
})

test("workflow stream builds websocket URLs from the configured API base", () => {
  const previousWindow = globalThis.window
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { location: { origin: "http://localhost:5173" } },
  })
  try {
    assert.equal(
      workflowStreamUrl("workflow-1", "https://api.example.test"),
      "wss://api.example.test/api/v1/workflows/workflow-1/stream",
    )
  } finally {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: previousWindow,
    })
  }
})

test("workflow stream consumes websocket events and terminal snapshots", async () => {
  const previousWindow = globalThis.window
  const previousWebSocket = globalThis.WebSocket
  const sockets: FakeWebSocket[] = []
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { location: { origin: "http://localhost:5173" } },
  })
  Object.defineProperty(globalThis, "WebSocket", {
    configurable: true,
    value: class extends FakeWebSocket {
      constructor(url: string) {
        super(url)
        sockets.push(this)
      }
    },
  })
  try {
    const events: number[] = []
    let terminalStatus = ""
    const stop = subscribeWorkflowUpdates({
      workflowId: "workflow-1",
      onEvent: (event) => events.push(event.sequence),
      onTerminal: (workflow) => {
        terminalStatus = workflow.status
      },
    })
    sockets[0].emit("not-json")
    sockets[0].emit(
      JSON.stringify({
        event: { sequence: 3 },
        type: "event",
      }),
    )
    sockets[0].emit(
      JSON.stringify({
        type: "workflow",
        workflow: { id: "workflow-1", status: "succeeded" },
      }),
    )
    await waitFor(() => terminalStatus === "succeeded")
    assert.deepEqual(events, [3])
    stop()
  } finally {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: previousWindow,
    })
    Object.defineProperty(globalThis, "WebSocket", {
      configurable: true,
      value: previousWebSocket,
    })
  }
})

test("workflow stream falls back to polling when websockets are unavailable", async () => {
  const previousWebSocket = globalThis.WebSocket
  Object.defineProperty(globalThis, "WebSocket", {
    configurable: true,
    value: undefined,
  })
  try {
    const events: number[] = []
    let fallbackUsed = false
    let terminalStatus = ""
    const stop = subscribeWorkflowUpdates({
      workflowId: "workflow-1",
      onEvent: (event) => events.push(event.sequence),
      onFallback: () => {
        fallbackUsed = true
      },
      onTerminal: (workflow) => {
        terminalStatus = workflow.status
      },
      readWorkflow: async () => ({ id: "workflow-1", status: "succeeded" }) as never,
      readWorkflowEvents: async () => ({ count: 1, data: [{ sequence: 7 }] }) as never,
    })
    await waitFor(() => terminalStatus === "succeeded")
    assert.equal(fallbackUsed, true)
    assert.deepEqual(events, [7])
    stop()
  } finally {
    Object.defineProperty(globalThis, "WebSocket", {
      configurable: true,
      value: previousWebSocket,
    })
  }
})

test("query model polls active durable workflows before legacy run status", () => {
  assert.equal(runDetailNeedsPolling(undefined), false)
  assert.equal(
    runDetailNeedsPolling({
      run: { status: "succeeded", workflow: runningWorkflow },
      summary: { workflow: succeededWorkflow },
    } as never),
    true,
  )
  assert.equal(
    runDetailNeedsPolling({
      run: { status: "running", workflow: succeededWorkflow },
      summary: { workflow: succeededWorkflow },
    } as never),
    true,
  )
  assert.equal(
    runDetailNeedsPolling({
      run: { status: "succeeded", workflow: succeededWorkflow },
      summary: { workflow: succeededWorkflow },
    } as never),
    false,
  )
  assert.equal(reportsNeedPolling([{ workflow: runningWorkflow }] as never), true)
  assert.equal(reportsNeedPolling([{ workflow: succeededWorkflow }] as never), false)
  assert.equal(
    providerStatusNeedsPolling({
      latest_update_job: { workflow: runningWorkflow },
    } as never),
    true,
  )
  assert.equal(providerStatusNeedsPolling(undefined), false)
})

test("query model exposes safe empty query fallbacks", () => {
  assert.equal(emptyFindingQueryPage(true), undefined)
  assert.deepEqual(emptyFindingQueryPage(false), { count: 0, data: [] })
  assert.deepEqual(dashboardSignalCountsFromApi(null), emptyDashboardSignalCounts)
  assert.deepEqual(dashboardSignalCountsFromApi(undefined), emptyDashboardSignalCounts)
  assert.deepEqual(
    dashboardSignalCountsFromApi({
      epss_buckets: { critical: 4, high: 3, low: 1, medium: 2 },
      high_epss: 5,
      internet_facing_criticals: 6,
    } as never),
    {
      epssBuckets: { critical: 4, high: 3, low: 1, medium: 2 },
      highEpss: 5,
      internetFacingCriticals: 6,
    },
  )
})

test("query model reads paginated collections until complete", async () => {
  const calls: Array<{ limit: number; offset: number }> = []

  const page = await readAllPages(async (pagination) => {
    calls.push(pagination)
    if (pagination.offset === 0) {
      return { count: 3, data: ["a", "b"] }
    }
    return { count: 3, data: ["c"] }
  })

  assert.deepEqual(page, { count: 3, data: ["a", "b", "c"] })
  assert.deepEqual(
    calls.map((call) => call.offset),
    [0, 2],
  )
})

test("query model reads project summaries with bounded failures", async () => {
  const controller = new AbortController()

  const result = await readProjectSummariesWithLimit(
    ["project-a", "project-b", "project-c"],
    controller.signal,
    async ({ project_id }, { signal }) => {
      assert.equal(signal, controller.signal)
      if (project_id === "project-b") {
        throw new Error("temporary read failure")
      }
      return { id: project_id } as never
    },
  )

  assert.deepEqual(result.failedProjectIds, ["project-b"])
  assert.deepEqual(Object.keys(result.summaries).sort(), [
    "project-a",
    "project-c",
  ])
})

test("query model propagates project summary aborts", async () => {
  const preAborted = new AbortController()
  preAborted.abort()

  await assert.rejects(
    readProjectSummariesWithLimit(["project-a"], preAborted.signal, async () => {
      throw new Error("should not read")
    }),
    { name: "AbortError" },
  )

  const abortDuringRead = new AbortController()
  const abortError = new Error("aborted in reader")

  await assert.rejects(
    readProjectSummariesWithLimit(
      ["project-a"],
      abortDuringRead.signal,
      async () => {
        abortDuringRead.abort()
        throw abortError
      },
    ),
    abortError,
  )
})

class FakeWebSocket {
  static CLOSING = 2

  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((message: { data: string }) => void) | null = null
  readyState = 1
  url: string

  constructor(url: string) {
    this.url = url
  }

  close() {
    this.readyState = 3
    this.onclose?.()
  }

  emit(data: string) {
    this.onmessage?.({ data })
  }
}

async function waitFor(predicate: () => boolean) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  assert.fail("condition was not met")
}
