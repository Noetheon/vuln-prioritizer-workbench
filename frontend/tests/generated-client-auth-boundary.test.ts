import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import test from "node:test"

const frontendRoot = new URL("..", import.meta.url)

function read(relativePath: string) {
  return readFileSync(new URL(relativePath, `${frontendRoot.href}/`), "utf8")
}

test("generated SDK and handwritten API wrapper stay on local access", () => {
  const generatorConfig = read("openapi-ts.config.ts")
  const sdk = read("src/client/sdk.gen.ts")
  const apiClient = read("src/api-client.ts")

  assert.match(generatorConfig, /auth:\s*false/)
  assert.equal(existsSync(new URL("src/client/core", `${frontendRoot.href}/`)), false)
  assert.equal(existsSync(new URL("src/client/client", `${frontendRoot.href}/`)), false)
  assert.equal(sdk.includes("security:"), false)
  assert.equal(sdk.includes("Authorization"), false)
  assert.equal(apiClient.includes("auth:"), false)
  assert.equal(apiClient.includes("access_token"), false)
  assert.equal(apiClient.includes("Authorization"), false)
})
