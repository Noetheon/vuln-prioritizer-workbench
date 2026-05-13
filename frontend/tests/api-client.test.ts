import assert from "node:assert/strict"
import test from "node:test"

import { ApiError, createApiFetch } from "../src/lib/api-client-errors.ts"

test("API fetch wrapper turns network failures into ApiError", async () => {
  const fetcher = createApiFetch(async () => {
    throw new TypeError("Failed to fetch")
  })

  await assert.rejects(
    fetcher("http://127.0.0.1:65535/api/v1/projects/"),
    (caught) => {
      assert.ok(caught instanceof ApiError)
      assert.equal(caught.status, 0)
      assert.deepEqual(caught.body, {
        detail:
          "The Workbench API request did not receive a response. Check that the backend is running and that same-origin or CORS settings allow this browser session.",
      })
      return true
    },
  )
})

test("API fetch wrapper preserves abort errors for query cancellation", async () => {
  const abortError = new DOMException("The operation was aborted.", "AbortError")
  const fetcher = createApiFetch(async () => {
    throw abortError
  })

  await assert.rejects(fetcher("http://127.0.0.1/api/v1/projects/"), (caught) => {
    assert.equal(caught, abortError)
    return true
  })
})

test("API fetch wrapper returns successful responses unchanged", async () => {
  const response = new Response("ok", { status: 200 })
  const fetcher = createApiFetch(async () => response)

  assert.equal(await fetcher("http://127.0.0.1/api/v1/projects/"), response)
})
