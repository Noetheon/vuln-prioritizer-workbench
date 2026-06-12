import assert from "node:assert/strict"
import test from "node:test"

import type { FindingPublic } from "../src/api-client"
import {
  findingAssetServiceLabel,
  findingPlannedAction,
} from "../src/lib/finding-queue-labels.ts"

function finding(overrides: Partial<FindingPublic>): FindingPublic {
  return {
    cve_id: "CVE-2021-44228",
    id: "finding-1",
    project_id: "project-1",
    status: "open",
    priority: "critical",
    ...overrides,
  } as FindingPublic
}

test("asset/service label combines asset and business service", () => {
  assert.equal(
    findingAssetServiceLabel(
      finding({ asset_name: "pay-api-01", business_service: "payments" }),
    ),
    "pay-api-01 · payments",
  )
  assert.equal(
    findingAssetServiceLabel(
      finding({ asset_name: null, asset_key: "edge-cache-01" }),
    ),
    "edge-cache-01",
  )
  assert.equal(
    findingAssetServiceLabel(finding({ business_service: "checkout" })),
    "checkout",
  )
  assert.equal(findingAssetServiceLabel(finding({})), "—")
})

test("planned action strips trailing period and falls back to review copy", () => {
  assert.equal(
    findingPlannedAction(
      finding({ recommended_action: "Upgrade log4j-core to 2.17.2." }),
    ),
    "Upgrade log4j-core to 2.17.2",
  )
  assert.equal(
    findingPlannedAction(finding({ recommended_action: "  " })),
    "Review with the asset owner and record the remediation path",
  )
  assert.equal(
    findingPlannedAction(finding({ recommended_action: null })),
    "Review with the asset owner and record the remediation path",
  )
})

test("planned action replaces provider boilerplate with a patch instruction", () => {
  assert.equal(
    findingPlannedAction(
      finding({
        component_name: "log4j-core",
        component_version: "2.14.1",
        recommended_action:
          "CISA KEV required action: For all affected software assets apply updates per vendor instructions.",
      }),
    ),
    "Patch log4j-core 2.14.1",
  )
  assert.equal(
    findingPlannedAction(
      finding({
        component_name: "xz",
        recommended_action:
          "A remediation sentence that is far too long to fit into one readable queue cell at all.",
      }),
    ),
    "Patch xz",
  )
})
