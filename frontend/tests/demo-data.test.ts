import assert from "node:assert/strict"
import test from "node:test"

import {
  DEMO_FINDING_ATTACK_CONTEXTS,
  DEMO_FINDINGS,
  DEMO_GOVERNANCE_ROLLUPS,
  DEMO_PROJECT,
  DEMO_PROVIDER_STATUS,
  DEMO_REPORTS,
  DEMO_SUMMARY,
  DEMO_TOP_SERVICES,
  DEMO_WAIVERS,
} from "../src/lib/demo-data.ts"
import { findingWhyNow } from "../src/lib/finding-urgency-summary.ts"

test("frontend demo preview mirrors the Online Shop demo workspace story", () => {
  const cves = new Set(DEMO_FINDINGS.map((finding) => finding.cve_id))

  assert.equal(DEMO_PROJECT.name, "Online Shop Demo Workspace")
  assert.equal(DEMO_FINDINGS.length, 24)
  assert.deepEqual([...cves].sort(), [
    "CVE-2020-1472",
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-34362",
    "CVE-2023-44487",
    "CVE-2024-3094",
    "CVE-2024-4577",
  ])
  assert.equal(DEMO_SUMMARY.finding_count, DEMO_FINDINGS.length)
  assert.equal(DEMO_SUMMARY.kev_hits, 21)
  assert.equal(DEMO_TOP_SERVICES[0]?.label, "payments")
})

test("frontend demo preview exposes governance, VEX, fixed, and unmapped states", () => {
  const statuses = new Set(DEMO_FINDINGS.map((finding) => finding.status))
  const xzFinding = DEMO_FINDINGS.find(
    (finding) => finding.cve_id === "CVE-2024-3094",
  )

  assert.ok(statuses.has("accepted"))
  assert.ok(statuses.has("suppressed"))
  assert.ok(statuses.has("fixed"))
  assert.ok(statuses.has("in_review"))
  assert.equal(DEMO_WAIVERS.length, 4)
  assert.equal(DEMO_GOVERNANCE_ROLLUPS.waiver_debt?.review_due_count, 1)
  assert.equal(DEMO_GOVERNANCE_ROLLUPS.waiver_debt?.expiring_soon_count, 1)
  assert.equal(xzFinding?.attack_mapped, false)
})

test("frontend demo preview keeps provider replay and report inventory honest", () => {
  const filenames = DEMO_REPORTS.map((report) => report.filename)

  assert.equal(DEMO_PROVIDER_STATUS.snapshot.locked_provider_data, true)
  assert.equal(DEMO_PROVIDER_STATUS.status, "degraded")
  assert.ok(DEMO_PROVIDER_STATUS.warnings?.[0]?.includes("reproducible"))
  assert.deepEqual(filenames, [
    "technical-report.md",
    "executive-report.html",
    "analysis-result.v1.json",
    "findings.csv",
    "results.sarif",
    "attack-navigator-layer.json",
    "evidence-bundle.zip",
  ])
  assert.ok(DEMO_REPORTS.every((report) => report.sha256.startsWith("demo-only")))
})

test("frontend demo ATT&CK mappings are reviewed defensive context only", () => {
  const rendered = JSON.stringify(DEMO_FINDING_ATTACK_CONTEXTS)

  assert.match(rendered, /Local curated demo mapping/)
  assert.match(rendered, /Reviewed defensive context only/)
  assert.doesNotMatch(rendered, /LLM/i)
  assert.doesNotMatch(rendered, /exploit/i)
  assert.doesNotMatch(rendered, /payload/i)
  assert.equal(DEMO_FINDING_ATTACK_CONTEXTS["demo-f24"], undefined)
})

test("frontend demo preview has signal-derived why-now summaries", () => {
  for (const finding of DEMO_FINDINGS) {
    const whyNow = findingWhyNow(finding)

    assert.notEqual(whyNow, finding.recommended_action)
    assert.match(
      whyNow,
      /KEV|EPSS|CVSS|internet-facing|production|accepted risk|VEX|fixed|review|remediation|open/i,
    )
  }
})
