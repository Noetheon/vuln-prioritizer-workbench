import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"

const evidenceCenterFile = new URL(
  "../src/components/reports/EvidenceCenter.tsx",
  import.meta.url,
)
const evidenceCenterSectionsFile = new URL(
  "../src/components/reports/EvidenceCenterSections.tsx",
  import.meta.url,
)
const evidenceCenterSummaryFile = new URL(
  "../src/components/reports/EvidenceCenterSummary.tsx",
  import.meta.url,
)
const evidenceCenterDecisionFile = new URL(
  "../src/components/reports/EvidenceCenterDecision.tsx",
  import.meta.url,
)
const evidenceCenterManifestFile = new URL(
  "../src/components/reports/EvidenceCenterManifest.tsx",
  import.meta.url,
)
const reportsStateFile = new URL(
  "../src/workbench/useReportsRouteState.ts",
  import.meta.url,
)

function text(url: URL) {
  return readFileSync(url, "utf8")
}

test("Evidence Center consumes selected run summaries and verification state", () => {
  const source = [
    evidenceCenterFile,
    evidenceCenterSectionsFile,
    evidenceCenterSummaryFile,
    evidenceCenterManifestFile,
  ]
    .map(text)
    .join("\n")

  assert.doesNotMatch(source, /void selectedRunSummary/)
  assert.match(text(evidenceCenterFile), /isDemo \|\| selectedReportRun/)
  assert.match(text(evidenceCenterDecisionFile), /isDemo \? DEMO_SUMMARY : selectedRunSummary/)
  assert.match(source, /verificationReportTarget/)
  assert.match(source, /verificationStatus/)
})

test("reports route state exposes evidence verification results to the UI", () => {
  const source = text(reportsStateFile)

  assert.match(source, /verificationReport,/)
  assert.match(source, /verificationReportTarget,/)
  assert.match(source, /verificationLoading,/)
})
