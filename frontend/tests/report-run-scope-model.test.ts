import assert from "node:assert/strict"
import test from "node:test"

import type { AnalysisRunPublic } from "../src/api-client"
import {
  CURRENT_PROJECT_STATE,
  currentProjectStateScope,
  defaultReportRunId,
  isProjectStateRun,
  isReportableRun,
  latestImportRunId,
  reportRunOptionLabel,
  reportRunOptions,
  reportRunName,
  reportRunScope,
  runFileLabel,
  runFindingCount,
} from "../src/components/reports/report-run-scope-model.ts"
import { normalizeSelectedRunId } from "../src/workbench/report-route-search.ts"

function run(overrides: Partial<AnalysisRunPublic>): AnalysisRunPublic {
  return {
    counts: { finding_count: 32 },
    filename: "trivy.json",
    finished_at: "2026-05-01T10:05:00Z",
    id: "run-import",
    input_type: "trivy-json",
    project_id: "project-1",
    provider_snapshot_id: null,
    started_at: "2026-05-01T10:00:00Z",
    status: "completed",
    ...overrides,
  } as AnalysisRunPublic
}

// Newest first, as the runs API returns them.
const reevaluation = run({
  counts: { finding_count: 1 },
  filename: null,
  id: "run-reevaluation",
  input_type: "reevaluation",
  started_at: "2026-05-03T09:00:00Z",
})
const failed = run({
  counts: { finding_count: 0 },
  filename: "cves.txt",
  id: "run-failed",
  input_type: "cve-list",
  started_at: "2026-05-02T09:00:00Z",
  status: "failed",
})
const providerUpdate = run({
  filename: null,
  id: "run-provider-update",
  input_type: "provider_update",
  started_at: "2026-05-02T08:00:00Z",
})
const projectState = run({
  counts: { finding_count: 30 },
  filename: null,
  id: "run-state",
  input_type: "project_state",
  started_at: "2026-05-04T08:00:00Z",
})
const latestImport = run({})
const olderImport = run({
  filename: "grype.json",
  id: "run-older",
  input_type: "grype-json",
  started_at: "2026-04-20T10:00:00Z",
})
const runs = [
  projectState,
  reevaluation,
  failed,
  providerUpdate,
  latestImport,
  olderImport,
]

test("reports describe the current project state by default", () => {
  assert.equal(defaultReportRunId(runs), CURRENT_PROJECT_STATE)
  const stillCurrent = { ...projectState, project_state_current: true }
  assert.equal(defaultReportRunId([stillCurrent, ...runs]), "run-state")
  assert.equal(defaultReportRunId([failed]), "")
  assert.equal(defaultReportRunId([]), "")
  assert.equal(latestImportRunId(runs), "run-import")
  assert.equal(latestImportRunId([reevaluation, projectState]), "")
})

test("provider updates are not report runs; failed runs cannot be reported", () => {
  assert.deepEqual(
    reportRunOptions(runs).map((item) => item.id),
    ["run-state", "run-reevaluation", "run-failed", "run-import", "run-older"],
  )
  assert.equal(isProjectStateRun(projectState), true)
  assert.equal(isReportableRun(failed), false)
  assert.equal(isReportableRun(providerUpdate), false)
  assert.equal(isReportableRun(reevaluation), true)
})

test("an explicit run choice wins over the default", () => {
  const ids = reportRunOptions(runs).map((item) => item.id)
  assert.equal(
    normalizeSelectedRunId(["run-older"], ids, defaultReportRunId(runs)),
    "run-older",
  )
  assert.equal(
    normalizeSelectedRunId(["missing"], ids, defaultReportRunId(runs)),
    CURRENT_PROJECT_STATE,
  )
})

test("run labels name the file, date, and finding count", () => {
  assert.equal(runFileLabel(reevaluation), "Re-evaluation")
  assert.equal(runFileLabel(projectState), "Project state")
  assert.match(reportRunOptionLabel(projectState), /^Project state · .+ · 30 findings$/)
  assert.equal(
    runFileLabel(
      run({
        filename: null,
        uploads: { input: { original_filename: "scan.sarif" } },
      } as Partial<AnalysisRunPublic>),
    ),
    "scan.sarif",
  )
  assert.equal(runFileLabel(run({ filename: null })), "trivy-json upload")
  assert.equal(runFindingCount(run({ counts: undefined })), null)
  assert.match(reportRunOptionLabel(latestImport), /^trivy\.json · .+ · 32 findings$/)
  assert.match(reportRunOptionLabel(reevaluation), /^Re-evaluation · .+ · 1 finding$/)
  assert.match(reportRunOptionLabel(failed), /· failed$/)
  assert.match(
    reportRunOptionLabel(run({ counts: {} })),
    /· findings$/,
  )
})

test("report history names the run each report covers", () => {
  assert.equal(reportRunName("run-import", runs), "trivy.json")
  assert.equal(reportRunName("run-state", runs), "Project state")
  assert.equal(reportRunName("0123456789abcdef", runs), "01234567")
})

test("the scope banner says what the report covers", () => {
  assert.equal(reportRunScope(null, runs), null)

  const latest = reportRunScope(latestImport, runs)
  assert.equal(latest?.tone, "info")
  assert.match(latest?.message ?? "", /^This report covers 32 findings from trivy\.json/)

  const older = reportRunScope(olderImport, runs)
  assert.equal(older?.tone, "warning")
  assert.match(older?.message ?? "", /A newer import exists: trivy\.json/)

  const partial = reportRunScope(reevaluation, runs)
  assert.equal(partial?.title, "Re-evaluation run selected")
  assert.match(partial?.message ?? "", /re-scored 1 finding/)

  assert.equal(reportRunScope(failed, runs)?.title, "This run did not complete")

  const recorded = reportRunScope(projectState, runs, { projectStateCurrent: true })
  assert.equal(recorded?.title, "Recorded project state")
  assert.match(recorded?.message ?? "", /covers the whole project as recorded on .+: 30 findings/)
  const outdated = reportRunScope(projectState, runs, { projectStateCurrent: false })
  assert.equal(outdated?.tone, "warning")
  assert.equal(
    reportRunScope({ ...projectState, project_state_current: false }, runs)?.tone,
    "warning",
  )
  assert.match(outdated?.message ?? "", /new ones fail because the project has changed/)
})

test("the current state banner counts the project's findings", () => {
  assert.match(currentProjectStateScope(32).message, /^Reports cover all 32 findings/)
  assert.match(currentProjectStateScope(1).message, /^Reports cover all 1 finding of/)
  assert.match(currentProjectStateScope(null).message, /^Reports cover all findings/)
  assert.equal(currentProjectStateScope(null).title, "Current project state")
})
