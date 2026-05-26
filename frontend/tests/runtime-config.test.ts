import assert from "node:assert/strict"
import test from "node:test"

import {
  isLocalApiBaseUrl,
  normalizeApiBaseUrl,
  workbenchApiUrl,
} from "../src/lib/runtime-config.ts"

test("normalizes same-origin API configuration to the generated /api paths", () => {
  assert.equal(normalizeApiBaseUrl(undefined), "")
  assert.equal(normalizeApiBaseUrl(""), "")
  assert.equal(normalizeApiBaseUrl("/api"), "")
  assert.equal(
    normalizeApiBaseUrl("   https://api.example.com/v1///"),
    "https://api.example.com/v1",
  )
  assert.equal(
    normalizeApiBaseUrl("https://api.example.com/?debug=1#top"),
    "https://api.example.com",
  )
  assert.equal(
    normalizeApiBaseUrl("https://api.example.com/"),
    "https://api.example.com",
  )
  assert.equal(normalizeApiBaseUrl("not a url"), "")
})

test("detects localhost API origins before production bundling", () => {
  assert.equal(isLocalApiBaseUrl(undefined), false)
  assert.equal(isLocalApiBaseUrl("not a url"), false)
  assert.equal(isLocalApiBaseUrl("http://localhost:8000"), true)
  assert.equal(isLocalApiBaseUrl("http://127.0.0.1:8000"), true)
  assert.equal(isLocalApiBaseUrl("http://[::1]:8000"), true)
  assert.equal(isLocalApiBaseUrl("https://api.example.com"), false)
})

test("builds runtime backend links from same-origin API configuration", () => {
  assert.equal(workbenchApiUrl("/docs"), "/docs")
  assert.equal(workbenchApiUrl("docs"), "/docs")
  assert.equal(workbenchApiUrl(null), "")
})
