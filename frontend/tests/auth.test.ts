import assert from "node:assert/strict"
import test from "node:test"

import { getCsrfToken } from "../src/auth.ts"

test("reads CSRF tokens from client-readable cookies", () => {
  assert.equal(getCsrfToken("vpw_csrf_token=abc123"), "abc123")
  assert.equal(getCsrfToken("other=1; XSRF-TOKEN=encoded%20token"), "encoded token")
  assert.equal(getCsrfToken("session=opaque"), "")
})
