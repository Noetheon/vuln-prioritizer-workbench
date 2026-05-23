import assert from "node:assert/strict"
import test from "node:test"

import type { AssetPublic } from "../src/api-client"
import {
  defaultAssetFilters,
  filterAssets,
  hasActiveAssetFilters,
} from "../src/components/assets/asset-filter-model.ts"

test("asset register filters match searchable identity fields", () => {
  const assets = [
    asset({ name: "checkout-web-01", asset_key: "checkout-01" }),
    asset({ name: "orders-api-01", asset_key: "orders-01" }),
    asset({ name: "worker", target_ref: "pkg:maven/log4j-core" }),
  ]

  assert.deepEqual(
    filterAssets(assets, { ...defaultAssetFilters, query: "orders" }).map(
      (entry) => entry.name,
    ),
    ["orders-api-01"],
  )
  assert.deepEqual(
    filterAssets(assets, { ...defaultAssetFilters, query: "log4j" }).map(
      (entry) => entry.name,
    ),
    ["worker"],
  )
})

test("asset register filters cover operational asset facets", () => {
  const assets = [
    asset({
      business_service: "checkout",
      criticality: "critical",
      environment: "production",
      exposure: "internet-facing",
      finding_count: 3,
      owner: "team-checkout",
      rescore_needed: true,
    }),
    asset({
      business_service: "catalog",
      criticality: "medium",
      environment: "development",
      exposure: "internal",
      finding_count: 0,
      owner: "team-catalog",
      rescore_needed: false,
    }),
  ]

  const filtered = filterAssets(assets, {
    ...defaultAssetFilters,
    criticality: "critical",
    environment: "production",
    exposure: "internet-facing",
    findings: "linked",
    owner: "checkout",
    rescore: "needed",
    service: "check",
  })

  assert.equal(filtered.length, 1)
  assert.equal(filtered[0]?.business_service, "checkout")
  assert.deepEqual(
    filterAssets(assets, { ...defaultAssetFilters, findings: "none" }).map(
      (entry) => entry.business_service,
    ),
    ["catalog"],
  )
})

test("asset register filter activity detects every non-default filter", () => {
  assert.equal(hasActiveAssetFilters(defaultAssetFilters), false)
  assert.equal(
    hasActiveAssetFilters({ ...defaultAssetFilters, exposure: "internal" }),
    true,
  )
  assert.equal(
    hasActiveAssetFilters({ ...defaultAssetFilters, query: " checkout " }),
    true,
  )
})

function asset(overrides: Partial<AssetPublic>): AssetPublic {
  return {
    asset_key: "asset-key",
    business_service: "payments",
    created_at: "2026-05-22T00:00:00Z",
    criticality: "medium",
    environment: "production",
    exposure: "internal",
    finding_count: 0,
    id: crypto.randomUUID(),
    name: "asset",
    owner: "team-payments",
    project_id: "project-1",
    rescore_needed: false,
    target_ref: "asset-key",
    updated_at: "2026-05-22T00:00:00Z",
    ...overrides,
  }
}
