import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"

const queriesFile = new URL(
  "../src/workbench/useWorkbenchQueries.ts",
  import.meta.url,
)
const queryModelFile = new URL(
  "../src/workbench/workbench-query-model.ts",
  import.meta.url,
)
const runtimeQueriesFile = new URL(
  "../src/workbench/useWorkbenchRuntimeQueries.ts",
  import.meta.url,
)
const reportsRouteStateFile = new URL(
  "../src/workbench/useReportsRouteState.ts",
  import.meta.url,
)
const ciWorkflowFile = new URL(
  "../../.github/workflows/ci.yml",
  import.meta.url,
)

function source(file = queriesFile) {
  return readFileSync(file, "utf8")
}

test("Workbench queries propagate abort signals into generated client calls", () => {
  const queries = source()

  assert.match(queries, /queryFn: \(\{ signal \}\)/)
  assert.match(queries, /readAllPages\(\(pagination\) =>/)
  assert.match(
    queries,
    /ProjectsService\.readProjects\(pagination,\s*\{ signal \}\)/,
  )
  assert.match(queries, /RunsService\.readProjectRuns\(\s*\{[^}]*\.\.\.pagination/s)
  assert.match(queries, /AssetsService\.readProjectAssets\(\s*\{[^}]*\.\.\.pagination/s)
  assert.match(queries, /WaiversService\.readProjectWaivers\(\s*\{[^}]*\.\.\.pagination/s)
  assert.match(queries, /readProjectSummary\(\s*\{ project_id: projectId \},\s*\{ signal \}/s)
  assert.match(queries, /readProjectFindings\(params, \{ signal \}\)/)
  assert.match(queries, /if \(signal\.aborted\) \{\s*throw caught\s*\}/s)
  assert.match(queries, /runDetailNeedsPolling/)
})

test("project summary fanout is concurrency-limited", () => {
  const queries = source()
  const queryModel = source(queryModelFile)

  assert.match(queryModel, /const PROJECT_SUMMARY_CONCURRENCY = 4/)
  assert.match(queries, /readProjectSummariesWithLimit\(/)
  assert.match(queries, /ProjectsService\.readProjectSummary/)
  assert.match(
    queryModel,
    /Math\.min\(PROJECT_SUMMARY_CONCURRENCY, projectIds\.length\)/,
  )
})

test("workbench query file delegates pure models to query model", () => {
  const queries = source()
  const queryModel = source(queryModelFile)

  assert.match(queries, /from "\.\/workbench-query-model"/)
  assert.doesNotMatch(queries, /function dashboardSignalCountsFromApi/)
  assert.doesNotMatch(queries, /function emptyFindingQueryPage/)
  assert.match(queryModel, /function dashboardSignalCountsFromApi/)
  assert.match(queryModel, /function emptyFindingQueryPage/)
})

test("runtime and report queries propagate abort signals", () => {
  const runtimeQueries = source(runtimeQueriesFile)
  const reportsRouteState = source(reportsRouteStateFile)

  assert.match(
    runtimeQueries,
    /ProvidersService\.readProviderStatus\(\{ signal \}\)/,
  )
  assert.match(runtimeQueries, /providerStatusNeedsPolling/)
  assert.match(runtimeQueries, /WorkbenchService\.workbenchStatus\(\{ signal \}\)/)
  assert.match(runtimeQueries, /WorkbenchService\.readDemoWorkspace\(\{ signal \}\)/)
  assert.match(
    reportsRouteState,
    /ReportsService\.readRunReports\(\{ run_id: selectedRunId \}, \{ signal \}\)/,
  )
  assert.match(reportsRouteState, /reportsNeedPolling/)
})

test("frontend CI typechecks unit and source-contract tests", () => {
  const ciWorkflow = source(ciWorkflowFile)

  assert.match(ciWorkflow, /Typecheck frontend tests/)
  assert.match(ciWorkflow, /make frontend-test-types/)
})
