import assert from "node:assert/strict"
import test from "node:test"
import type { WorkbenchSessionPublic } from "../src/api-client"
import { shellIdentity } from "../src/lib/workbench-session.ts"

const proxySession: WorkbenchSessionPublic = {
  auth_mode: "proxy",
  display_name: "Alice Example",
  logout_url: "/oauth2/sign_out",
  user: "alice@example.com",
  user_id: "7b8e7a9c-0d5c-5a55-9d2b-9a6f0d1c2e3f",
}

test("local mode and unloaded sessions keep the local workspace label", () => {
  const local = {
    label: "Local workspace",
    signOutUrl: null,
    statusLabel: "Local workspace status",
  }
  assert.deepEqual(shellIdentity(undefined), local)
  assert.deepEqual(
    shellIdentity({
      ...proxySession,
      auth_mode: "local",
      display_name: "Local Workbench",
      logout_url: null,
    }),
    local,
  )
})

test("team mode names the signed-in user and offers the proxy sign-out", () => {
  assert.deepEqual(shellIdentity(proxySession), {
    label: "Alice Example",
    signOutUrl: "/oauth2/sign_out",
    statusLabel: "Signed in as alice@example.com",
  })
  assert.deepEqual(
    shellIdentity({ ...proxySession, display_name: " ", logout_url: null }),
    {
      label: "alice@example.com",
      signOutUrl: null,
      statusLabel: "Signed in as alice@example.com",
    },
  )
})
