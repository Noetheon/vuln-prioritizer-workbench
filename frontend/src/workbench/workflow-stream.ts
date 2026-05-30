import type {
  WorkflowEventPublic,
  WorkflowEventsPublic,
  WorkflowRunPublic,
} from "../api-client"
import { workflowIsTerminal } from "./workflow-model.ts"

type WorkflowStreamMessage =
  | { type: "workflow"; workflow: WorkflowRunPublic }
  | { type: "event"; event: WorkflowEventPublic }
  | { type: "error"; detail: string }

type SubscribeWorkflowUpdatesOptions = {
  workflowId: string
  apiBase?: string
  onEvent?: (event: WorkflowEventPublic) => void
  onFallback?: () => void
  onWorkflow?: (workflow: WorkflowRunPublic) => void
  onTerminal?: (workflow: WorkflowRunPublic) => void
  readWorkflow?: (workflowId: string) => Promise<WorkflowRunPublic>
  readWorkflowEvents?: (workflowId: string) => Promise<WorkflowEventsPublic>
}

export function subscribeWorkflowUpdates({
  workflowId,
  apiBase,
  onEvent,
  onFallback,
  onWorkflow,
  onTerminal,
  readWorkflow,
  readWorkflowEvents,
}: SubscribeWorkflowUpdatesOptions) {
  let stopped = false
  let websocket: WebSocket | null = null
  let fallbackTimer: ReturnType<typeof setTimeout> | null = null
  let fallbackStarted = false
  let latestWorkflow: WorkflowRunPublic | null = null
  let latestSequence = 0

  const stop = () => {
    stopped = true
    if (fallbackTimer) {
      clearTimeout(fallbackTimer)
    }
    if (websocket && websocket.readyState < WebSocket.CLOSING) {
      websocket.close()
    }
  }

  const finishIfTerminal = (workflow: WorkflowRunPublic) => {
    latestWorkflow = workflow
    onWorkflow?.(workflow)
    if (workflowIsTerminal(workflow)) {
      onTerminal?.(workflow)
      stop()
      return true
    }
    return false
  }

  const startFallback = () => {
    if (fallbackStarted || stopped) return
    fallbackStarted = true
    onFallback?.()
    const poll = async () => {
      if (stopped) return
      const readers = await workflowReaders(readWorkflow, readWorkflowEvents)
      try {
        const [workflow, events] = await Promise.all([
          readers.readWorkflow(workflowId),
          readers.readWorkflowEvents(workflowId),
        ])
        for (const event of events.data ?? []) {
          if (event.sequence <= latestSequence) continue
          latestSequence = event.sequence
          onEvent?.(event)
        }
        if (finishIfTerminal(workflow)) return
      } finally {
        if (!stopped) {
          fallbackTimer = setTimeout(poll, 3000)
        }
      }
    }
    void poll()
  }

  const url = workflowStreamUrl(workflowId, apiBase)
  if (!url || typeof WebSocket === "undefined") {
    startFallback()
    return stop
  }

  websocket = new WebSocket(url)
  websocket.onmessage = (message) => {
    const parsed = parseWorkflowStreamMessage(message.data)
    if (!parsed || parsed.type === "error") return
    if (parsed.type === "workflow") {
      finishIfTerminal(parsed.workflow)
      return
    }
    latestSequence = Math.max(latestSequence, parsed.event.sequence)
    onEvent?.(parsed.event)
  }
  websocket.onerror = () => startFallback()
  websocket.onclose = () => {
    if (!stopped && !workflowIsTerminal(latestWorkflow)) {
      startFallback()
    }
  }
  return stop
}

export function workflowStreamUrl(workflowId: string, apiBase = "") {
  if (typeof window === "undefined") return null
  const httpBase = apiBase || window.location.origin
  const url = new URL(`/api/v1/workflows/${workflowId}/stream`, httpBase)
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
  return url.toString()
}

async function workflowReaders(
  readWorkflow: SubscribeWorkflowUpdatesOptions["readWorkflow"],
  readWorkflowEvents: SubscribeWorkflowUpdatesOptions["readWorkflowEvents"],
) {
  if (readWorkflow && readWorkflowEvents) {
    return { readWorkflow, readWorkflowEvents }
  }
  const { WorkflowsService } = await import("../api-client")
  return {
    readWorkflow: (workflowId: string) =>
      WorkflowsService.readWorkflow({ workflow_id: workflowId }),
    readWorkflowEvents: (workflowId: string) =>
      WorkflowsService.readWorkflowEvents({
        workflow_id: workflowId,
        limit: 1000,
      }),
  }
}

function parseWorkflowStreamMessage(value: unknown): WorkflowStreamMessage | null {
  if (typeof value !== "string") return null
  try {
    const parsed = JSON.parse(value) as WorkflowStreamMessage
    if (parsed.type === "workflow" || parsed.type === "event" || parsed.type === "error") {
      return parsed
    }
  } catch {
    return null
  }
  return null
}
