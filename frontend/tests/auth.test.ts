import assert from "node:assert/strict"
import test from "node:test"

import {
  clearAccessToken,
  csrfHeaderForMethod,
  getAccessToken,
  getCsrfToken,
  isLoggedIn,
  setAccessToken,
  withCsrfHeader,
} from "../src/auth.ts"
import { shouldClearAuthForApiError } from "../src/lib/auth-errors.ts"

type DocumentStub = {
  cookie: string
  querySelector: (selector: string) => { content: string } | null
}

function withDocument<T>(documentStub: DocumentStub, callback: () => T): T {
  const originalDocument = Reflect.get(globalThis, "document")
  const hadDocument = Reflect.has(globalThis, "document")

  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: documentStub,
    writable: true,
  })

  try {
    return callback()
  } finally {
    if (hadDocument) {
      Object.defineProperty(globalThis, "document", {
        configurable: true,
        value: originalDocument,
        writable: true,
      })
    } else {
      Reflect.deleteProperty(globalThis, "document")
    }
  }
}

test("reads CSRF tokens from client-readable cookies", () => {
  assert.equal(getCsrfToken("vpw_csrf_token=abc123"), "abc123")
  assert.equal(getCsrfToken("other=1; XSRF-TOKEN=encoded%20token"), "encoded token")
  assert.equal(getCsrfToken("vpw_csrf_token=%E0%A4%A"), "%E0%A4%A")
  assert.equal(getCsrfToken("session=opaque"), "")
})

test("clears auth only for unauthenticated API errors", () => {
  assert.equal(shouldClearAuthForApiError({ status: 401 }), true)
  assert.equal(shouldClearAuthForApiError({ status: 403 }), false)
  assert.equal(shouldClearAuthForApiError({ status: "401" }), false)
  assert.equal(shouldClearAuthForApiError(new Error("not api")), false)
})

test("falls back to CSRF meta tags when readable cookies are absent", () => {
  withDocument(
    {
      cookie: "session=opaque",
      querySelector: (selector) =>
        selector === 'meta[name="csrf-token"]'
          ? { content: " meta-token " }
          : null,
    },
    () => {
      assert.equal(getCsrfToken(), "meta-token")
    },
  )
})

test("falls back to alternate CSRF meta names", () => {
  withDocument(
    {
      cookie: "",
      querySelector: (selector) =>
        selector === 'meta[name="vpw-csrf-token"]'
          ? { content: " alternate-meta-token " }
          : null,
    },
    () => {
      assert.equal(getCsrfToken(), "alternate-meta-token")
    },
  )
})

test("only emits CSRF headers for unsafe methods with available tokens", () => {
  assert.equal(csrfHeaderForMethod("GET"), undefined)

  withDocument(
    {
      cookie: "vpw_csrf=write-token",
      querySelector: () => null,
    },
    () => {
      assert.deepEqual(csrfHeaderForMethod("post"), {
        "X-CSRF-Token": "write-token",
      })
    },
  )
})

test("adds missing CSRF headers without replacing explicit headers", () => {
  withDocument(
    {
      cookie: "vpw_csrf_token=request-token",
      querySelector: () => null,
    },
    () => {
      const safeRequest = new Request("https://example.test/projects", {
        method: "GET",
      })
      assert.equal(withCsrfHeader(safeRequest), safeRequest)

      const existingHeaderRequest = new Request("https://example.test/projects", {
        headers: { "X-CSRF-Token": "caller-token" },
        method: "POST",
      })
      assert.equal(withCsrfHeader(existingHeaderRequest), existingHeaderRequest)
      assert.equal(
        existingHeaderRequest.headers.get("X-CSRF-Token"),
        "caller-token",
      )

      const request = new Request("https://example.test/projects", {
        method: "POST",
      })
      const nextRequest = withCsrfHeader(request)

      assert.notEqual(nextRequest, request)
      assert.equal(nextRequest.headers.get("X-CSRF-Token"), "request-token")
    },
  )
})

test("keeps unsafe requests unchanged when no CSRF token is available", () => {
  const request = new Request("https://example.test/projects", {
    method: "DELETE",
  })

  assert.equal(withCsrfHeader(request), request)
})

test("tracks same-tab authentication without exposing legacy tokens", () => {
  clearAccessToken()
  assert.equal(isLoggedIn(), false)

  setAccessToken("legacy-token")

  assert.equal(isLoggedIn(), true)
  assert.equal(getAccessToken(), "")

  clearAccessToken()
  assert.equal(isLoggedIn(), false)
})

test("treats readable CSRF cookies as authenticated and clears them on logout", () => {
  const writes: string[] = []
  const documentStub = {
    querySelector: () => null,
  }
  Object.defineProperty(documentStub, "cookie", {
    configurable: true,
    get: () => "vpw_csrf_token=readable-token",
    set: (value: string) => {
      writes.push(value)
    },
  })

  withDocument(documentStub as DocumentStub, () => {
    assert.equal(isLoggedIn(), true)

    clearAccessToken()

    assert.ok(writes.some((value) => value.startsWith("vpw_csrf_token=")))
    assert.ok(writes.every((value) => value.includes("Max-Age=0")))
  })
})
