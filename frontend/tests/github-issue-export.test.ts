import assert from "node:assert/strict"
import test from "node:test"
import {
  buildGitHubIssueExportRequest,
  githubIssueExportReadiness,
  isValidGitHubRepository,
} from "../src/lib/github-issue-export.ts"

test("issue creation names the configured token environment variable", () => {
  assert.deepEqual(
    buildGitHubIssueExportRequest({
      findingIds: ["finding-1"],
      repository: " example/security ",
      tokenEnv: "GITHUB_TOKEN",
    }),
    {
      finding_ids: ["finding-1"],
      repository: "example/security",
      dry_run: false,
      token_env: "GITHUB_TOKEN",
    },
  )
})

test("issue creation readiness requires a configured credential source", () => {
  assert.deepEqual(githubIssueExportReadiness(undefined), {
    ready: false,
    reason: "GitHub issue creation is unavailable until export settings load.",
    tokenEnv: null,
  })
  assert.deepEqual(
    githubIssueExportReadiness({ token_env: "VPW_GITHUB_TOKEN", token_configured: false }),
    {
      ready: false,
      reason:
        "Set VPW_GITHUB_TOKEN in the environment of the Workbench process to create issues.",
      tokenEnv: "VPW_GITHUB_TOKEN",
    },
  )
  assert.deepEqual(
    githubIssueExportReadiness({ token_env: "GITHUB_TOKEN", token_configured: true }),
    { ready: true, tokenEnv: "GITHUB_TOKEN" },
  )
})

test("repository validation accepts owner/name only", () => {
  assert.equal(isValidGitHubRepository("example/security"), true)
  assert.equal(isValidGitHubRepository(" example/security "), true)
  assert.equal(isValidGitHubRepository("example"), false)
  assert.equal(isValidGitHubRepository("https://github.com/example/security"), false)
})
