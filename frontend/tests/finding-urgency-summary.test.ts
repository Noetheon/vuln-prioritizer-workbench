import assert from "node:assert/strict"
import test from "node:test"

import { findingWhyNow } from "../src/lib/finding-urgency-summary.ts"

type FindingFixture = Parameters<typeof findingWhyNow>[0]

function finding(overrides: Partial<FindingFixture>) {
  return {
    asset_criticality: null,
    asset_environment: null,
    business_service: null,
    cvss_base_score: null,
    epss: null,
    exposure: null,
    in_kev: false,
    rationale: null,
    recommended_action: null,
    status: "open",
    suppressed_by_vex: false,
    under_investigation: false,
    waived: false,
    ...overrides,
  } as FindingFixture
}

test("finding why-now summarizes active exploitation and asset-context signals", () => {
  const whyNow = findingWhyNow(
    finding({
      asset_criticality: "critical",
      asset_environment: "production",
      cvss_base_score: 9.8,
      epss: 0.944,
      exposure: "internet-facing",
      in_kev: true,
    }),
  )

  assert.match(whyNow, /CISA KEV/)
  assert.match(whyNow, /EPSS 94%/)
  assert.match(whyNow, /CVSS 9\.8/)
  assert.match(whyNow, /internet-facing exposure/)
  assert.match(whyNow, /remediation work is open/)
})

test("finding why-now separates governance from remediation action copy", () => {
  const whyNow = findingWhyNow(
    finding({
      cvss_base_score: 9.8,
      epss: 0.94,
      in_kev: true,
      recommended_action: "Patch immediately.",
      status: "accepted",
      waived: true,
    }),
  )

  assert.match(whyNow, /Governance review/)
  assert.match(whyNow, /accepted risk/)
  assert.doesNotMatch(whyNow, /Patch immediately/)
})

test("finding why-now keeps VEX suppression and fixed states explicit", () => {
  assert.match(
    findingWhyNow(finding({ status: "suppressed", suppressed_by_vex: true })),
    /VEX suppression/,
  )
  assert.match(findingWhyNow(finding({ status: "fixed" })), /fixed evidence/)
})

test("finding why-now falls back to stored rationale only when no queue signals exist", () => {
  const whyNow = findingWhyNow(
    finding({
      rationale: "Stored analyst rationale.",
      status: undefined,
    }),
  )

  assert.equal(whyNow, "Stored analyst rationale.")
})
