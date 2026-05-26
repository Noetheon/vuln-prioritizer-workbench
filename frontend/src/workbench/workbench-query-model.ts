import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  DashboardSignalCountsPublic,
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingPublic,
  ProjectDecisionSummaryPublic,
} from "../api-client"
import type { DashboardSignalCounts } from "../components/dashboard/dashboard-model"

export type RunDetailQueryData = {
  run: AnalysisRunPublic
  summary: AnalysisRunSummaryPublic
}

export type FindingDetailQueryData = {
  detail: FindingDetailPublic
  explanation: FindingExplanationPublic | null
  explanationWarning: string
}

export type ProjectSummariesQueryData = {
  failedProjectIds: string[]
  summaries: Record<string, ProjectDecisionSummaryPublic>
}

export type CollectionPage<T> = {
  count: number
  data: T[]
}

type ReadProjectSummary = (
  params: { project_id: string },
  options: { signal: AbortSignal },
) => Promise<ProjectDecisionSummaryPublic>

export const RUN_DETAIL_POLL_STATUSES = new Set(["pending", "running"])
export const PROJECT_SUMMARY_CONCURRENCY = 4
export const ASSET_FINDINGS_PAGE_LIMIT = 500
export const WORKBENCH_COLLECTION_PAGE_LIMIT = 500

export const emptyDashboardSignalCounts: DashboardSignalCounts = {
  highEpss: 0,
  internetFacingCriticals: 0,
  epssBuckets: {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  },
}

export function emptyFindingQueryPage(enabled: boolean) {
  return enabled ? undefined : { count: 0, data: [] as FindingPublic[] }
}

export async function readAllPages<T>(
  readPage: (pagination: {
    limit: number
    offset: number
  }) => Promise<CollectionPage<T>>,
): Promise<CollectionPage<T>> {
  const data: T[] = []
  let count = 0
  let offset = 0
  let received = 0
  do {
    const page = await readPage({
      limit: WORKBENCH_COLLECTION_PAGE_LIMIT,
      offset,
    })
    count = page.count
    received = page.data.length
    data.push(...page.data)
    offset += received
  } while (received > 0 && offset < count)
  return { count, data }
}

export async function readProjectSummariesWithLimit(
  projectIds: readonly string[],
  signal: AbortSignal,
  readProjectSummary: ReadProjectSummary,
): Promise<ProjectSummariesQueryData> {
  const summaries: Record<string, ProjectDecisionSummaryPublic> = {}
  const failedProjectIds: string[] = []
  let nextIndex = 0

  async function readNextProject() {
    while (nextIndex < projectIds.length) {
      if (signal.aborted) {
        throw new DOMException("Project summary query aborted", "AbortError")
      }
      const index = nextIndex
      nextIndex += 1
      const projectId = projectIds[index]
      try {
        summaries[projectId] = await readProjectSummary(
          { project_id: projectId },
          { signal },
        )
      } catch (caught) {
        if (signal.aborted) {
          throw caught
        }
        failedProjectIds.push(projectId)
      }
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(PROJECT_SUMMARY_CONCURRENCY, projectIds.length) },
      readNextProject,
    ),
  )
  return { failedProjectIds, summaries }
}

export function dashboardSignalCountsFromApi(
  signalCounts: DashboardSignalCountsPublic | null | undefined,
): DashboardSignalCounts {
  const buckets = signalCounts?.epss_buckets
  return {
    highEpss: signalCounts?.high_epss ?? 0,
    internetFacingCriticals: signalCounts?.internet_facing_criticals ?? 0,
    epssBuckets: {
      low: buckets?.low ?? 0,
      medium: buckets?.medium ?? 0,
      high: buckets?.high ?? 0,
      critical: buckets?.critical ?? 0,
    },
  }
}
