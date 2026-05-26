import { useQuery } from "@tanstack/react-query"

import {
  type AssetPublic,
  AssetsService,
  type FindingExplanationPublic,
  type FindingPublic,
  FindingsService,
  type FindingsReadProjectFindingsData,
  type ProjectPublic,
  ProjectsService,
  RunsService,
  WaiversService,
} from "../api-client"
import {
  demoFindingDetailForId,
  demoFindingExplanationForDetail,
} from "../components/finding-detail/finding-detail-model"
import { matchesAsset } from "../components/assets/asset-model"
import { apiErrorMessage } from "../lib/app-errors"
import { DEMO_MODE_ENABLED } from "../lib/runtime-config"
import {
  ASSET_FINDINGS_PAGE_LIMIT,
  RUN_DETAIL_POLL_STATUSES,
  type FindingDetailQueryData,
  type ProjectSummariesQueryData,
  type RunDetailQueryData,
  readAllPages,
  readProjectSummariesWithLimit,
} from "./workbench-query-model"
import { workbenchQueryKeys } from "./workbench-query-keys"

export {
  dashboardSignalCountsFromApi,
  emptyDashboardSignalCounts,
  emptyFindingQueryPage,
} from "./workbench-query-model"

export function useProjectsQuery() {
  return useQuery({
    queryFn: ({ signal }) =>
      readAllPages((pagination) =>
        ProjectsService.readProjects(pagination, { signal }),
      ),
    queryKey: workbenchQueryKeys.projects(),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectSummariesQuery(projects: readonly ProjectPublic[]) {
  const projectIds = projects.map((project) => project.id)
  return useQuery<ProjectSummariesQueryData>({
    enabled: projectIds.length > 0,
    queryFn: ({ signal }) =>
      readProjectSummariesWithLimit(
        projectIds,
        signal,
        ProjectsService.readProjectSummary,
      ),
    queryKey: workbenchQueryKeys.projectSummaries(projectIds),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectSummaryQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: ({ signal }) =>
      ProjectsService.readProjectSummary({ project_id: projectId }, { signal }),
    queryKey: workbenchQueryKeys.projectSummary(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectDashboardQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: ({ signal }) =>
      ProjectsService.readProjectDashboard({ project_id: projectId }, { signal }),
    queryKey: workbenchQueryKeys.projectDashboard(projectId),
    retry: false,
    staleTime: 10_000,
  })
}

export function useProjectAttackSummaryQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: ({ signal }) =>
      ProjectsService.readProjectAttackSummary(
        { project_id: projectId },
        { signal },
      ),
    queryKey: workbenchQueryKeys.projectAttackSummary(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectGovernanceRollupsQuery(projectId: string) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: ({ signal }) =>
      ProjectsService.readProjectGovernanceRollups({
        project_id: projectId,
        limit: 5,
      }, { signal }),
    queryKey: workbenchQueryKeys.projectGovernanceRollups(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectRunsQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: ({ signal }) =>
      readAllPages((pagination) =>
        RunsService.readProjectRuns({
          project_id: projectId,
          ...pagination,
        }, { signal }),
      ),
    queryKey: workbenchQueryKeys.projectRuns(projectId),
    retry: false,
    staleTime: 15_000,
  })
}

export function useProjectAssetsQuery({
  projectId,
}: {
  projectId: string
}) {
  return useQuery({
    enabled: Boolean(projectId),
    queryFn: ({ signal }) =>
      readAllPages((pagination) =>
        AssetsService.readProjectAssets({
          project_id: projectId,
          ...pagination,
        }, { signal }),
      ),
    queryKey: workbenchQueryKeys.assets(projectId),
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
    queryFn: async ({ signal }) => {
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
        }, { signal })
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
    queryFn: async ({ signal }) => {
      const [run, summary] = await Promise.all([
        RunsService.readRun({ run_id: runId }, { signal }),
        RunsService.readRunSummary({ run_id: runId }, { signal }),
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

export function useWaiversQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: ({ signal }) =>
      readAllPages((pagination) =>
        WaiversService.readProjectWaivers({
          project_id: projectId,
          ...pagination,
        }, { signal }),
      ),
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
    queryFn: ({ signal }) => FindingsService.readProjectFindings(params, { signal }),
    queryKey: workbenchQueryKeys.findings(params),
    retry: false,
    staleTime: 10_000,
  })
}

export function useFindingDetailQuery(findingId: string | null) {
  return useQuery<FindingDetailQueryData>({
    enabled: Boolean(findingId),
    queryFn: async ({ signal }) => {
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
      }, { signal })
      let explanation: FindingExplanationPublic | null = null
      let explanationWarning = ""
      try {
        explanation = await FindingsService.explainFinding({
          finding_id: findingId,
        }, { signal })
      } catch (caught) {
        if (signal.aborted) {
          throw caught
        }
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
