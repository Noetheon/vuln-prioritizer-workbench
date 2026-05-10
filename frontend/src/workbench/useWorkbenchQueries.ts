import { useQuery } from "@tanstack/react-query"

import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
  type AssetPublic,
  type DashboardSignalCountsPublic,
  AssetsService,
  type FindingDetailPublic,
  type FindingExplanationPublic,
  type FindingPublic,
  FindingsService,
  type FindingsReadProjectFindingsData,
  type ProjectDecisionSummaryPublic,
  type ProjectPublic,
  ProjectsService,
  RunsService,
  WaiversService,
  ApiTokensService,
} from "../api-client"
import {
  demoFindingDetailForId,
  demoFindingExplanationForDetail,
} from "../components/finding-detail/finding-detail-model"
import { matchesAsset } from "../components/assets/asset-model"
import type { DashboardSignalCounts } from "../components/dashboard/dashboard-model"
import { apiErrorMessage } from "../lib/app-errors"
import { DEMO_MODE_ENABLED } from "../lib/runtime-config"
import { workbenchQueryKeys } from "./workbench-query-keys"

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

const RUN_DETAIL_POLL_STATUSES = new Set(["pending", "running"])

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

function emptyFindingPage() {
  return { count: 0, data: [] as FindingPublic[] }
}

const ASSET_FINDINGS_PAGE_LIMIT = 500

export function useProjectsQuery() {
  return useQuery({
    queryFn: () => ProjectsService.readProjects(),
    queryKey: workbenchQueryKeys.projects(),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectSummariesQuery(projects: readonly ProjectPublic[]) {
  const projectIds = projects.map((project) => project.id)
  return useQuery<ProjectSummariesQueryData>({
    enabled: projectIds.length > 0,
    queryFn: async () => {
      const entries = await Promise.allSettled(
        projectIds.map((projectId) =>
          ProjectsService.readProjectSummary({ project_id: projectId }),
        ),
      )
      const summaries: Record<string, ProjectDecisionSummaryPublic> = {}
      const failedProjectIds: string[] = []
      entries.forEach((entry, index) => {
        if (entry.status === "fulfilled") {
          summaries[projectIds[index]] = entry.value
        } else {
          failedProjectIds.push(projectIds[index])
        }
      })
      return { failedProjectIds, summaries }
    },
    queryKey: workbenchQueryKeys.projectSummaries(projectIds),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectSummaryQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: () => ProjectsService.readProjectSummary({ project_id: projectId }),
    queryKey: workbenchQueryKeys.projectSummary(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectDashboardQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: () => ProjectsService.readProjectDashboard({ project_id: projectId }),
    queryKey: workbenchQueryKeys.projectDashboard(projectId),
    retry: false,
    staleTime: 10_000,
  })
}

export function useProjectAttackSummaryQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: () =>
      ProjectsService.readProjectAttackSummary({ project_id: projectId }),
    queryKey: workbenchQueryKeys.projectAttackSummary(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectGovernanceRollupsQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: () =>
      ProjectsService.readProjectGovernanceRollups({
        project_id: projectId,
        limit: 5,
      }),
    queryKey: workbenchQueryKeys.projectGovernanceRollups(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectRunsQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: () => RunsService.readProjectRuns({ project_id: projectId }),
    queryKey: workbenchQueryKeys.projectRuns(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectAssetsQuery({
  owner,
  projectId,
  service,
}: {
  owner: string
  projectId: string
  service: string
}) {
  const ownerFilter = owner.trim()
  const serviceFilter = service.trim()
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: () =>
      AssetsService.readProjectAssets({
        owner: ownerFilter || undefined,
        project_id: projectId,
        service: serviceFilter || undefined,
      }),
    queryKey: workbenchQueryKeys.assets(projectId, {
      owner: ownerFilter,
      service: serviceFilter,
    }),
    retry: false,
    staleTime: 10_000,
  })
}

export function useAssetFindingsQuery({
  asset,
  projectId,
}: {
  asset: AssetPublic | null
  projectId: string
}) {
  return useQuery({
    enabled: Boolean(projectId && asset),
    queryFn: async () => {
      if (!asset) {
        return [] as FindingPublic[]
      }
      const findings: FindingPublic[] = []
      let offset = 0
      let total = 0
      let received = 0
      do {
        const page = await FindingsService.readProjectFindings({
          asset_id: asset.id,
          limit: ASSET_FINDINGS_PAGE_LIMIT,
          offset,
          project_id: projectId,
          sort: "operational",
        })
        findings.push(
          ...page.data.filter((finding) => matchesAsset(finding, asset)),
        )
        total = page.count
        received = page.data.length
        offset += received
      } while (received > 0 && offset < total)
      return findings
    },
    queryKey: workbenchQueryKeys.assetFindings(projectId, asset?.id ?? null),
    retry: false,
    staleTime: 10_000,
  })
}

export function useRunDetailQuery(runId: string, enabled: boolean) {
  return useQuery<RunDetailQueryData>({
    enabled: enabled && Boolean(runId),
    queryFn: async () => {
      const [run, summary] = await Promise.all([
        RunsService.readRun({ run_id: runId }),
        RunsService.readRunSummary({ run_id: runId }),
      ])
      return { run, summary }
    },
    queryKey: workbenchQueryKeys.runDetail(runId),
    refetchInterval: (query) => {
      const status = query.state.data?.run.status
      return status && RUN_DETAIL_POLL_STATUSES.has(status) ? 3000 : false
    },
    retry: false,
    staleTime: 15_000,
  })
}

export function useApiTokensQuery(enabled: boolean) {
  return useQuery({
    enabled,
    queryFn: () => ApiTokensService.listApiTokens(),
    queryKey: workbenchQueryKeys.apiTokens(),
    retry: false,
    staleTime: 15_000,
  })
}

export function useWaiversQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: () => WaiversService.readProjectWaivers({ project_id: projectId }),
    queryKey: workbenchQueryKeys.waivers(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useFindingsQuery(
  params: FindingsReadProjectFindingsData,
  enabled: boolean,
) {
  return useQuery({
    enabled,
    queryFn: () => FindingsService.readProjectFindings(params),
    queryKey: workbenchQueryKeys.findings(params),
    retry: false,
    staleTime: 10_000,
  })
}

export function useFindingDetailQuery(findingId: string | null) {
  return useQuery<FindingDetailQueryData>({
    enabled: Boolean(findingId),
    queryFn: async () => {
      if (!findingId) {
        throw new Error("findingId is required")
      }
      const demoDetail = DEMO_MODE_ENABLED && findingId.startsWith("demo-")
        ? demoFindingDetailForId(findingId)
        : null
      if (demoDetail) {
        return {
          detail: demoDetail,
          explanation: demoFindingExplanationForDetail(demoDetail),
          explanationWarning: "",
        }
      }

      const detail = await FindingsService.readFinding({
        finding_id: findingId,
      })
      let explanation: FindingExplanationPublic | null = null
      let explanationWarning = ""
      try {
        explanation = await FindingsService.explainFinding({
          finding_id: findingId,
        })
      } catch (caught) {
        explanationWarning = apiErrorMessage(
          "Priority explanation unavailable",
          caught,
        )
      }
      return { detail, explanation, explanationWarning }
    },
    queryKey: workbenchQueryKeys.findingDetail(findingId),
    retry: false,
    staleTime: 10_000,
  })
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

export function emptyFindingQueryPage(enabled: boolean) {
  return enabled ? undefined : emptyFindingPage()
}
