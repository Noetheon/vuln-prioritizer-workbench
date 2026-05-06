import { useQuery } from "@tanstack/react-query"

import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
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
import type { EpssBucketCounts } from "../lib/chart-data"
import { DEMO_MODE_ENABLED } from "../lib/runtime-config"
import { workbenchQueryKeys } from "./workbench-query-keys"

export type DashboardSignalCounts = {
  highEpss: number
  internetFacingCriticals: number
  epssBuckets: EpssBucketCounts
}

export type RunDetailQueryData = {
  run: AnalysisRunPublic
  summary: AnalysisRunSummaryPublic
}

export type FindingDetailQueryData = {
  detail: FindingDetailPublic
  explanation: FindingExplanationPublic | null
  explanationWarning: string
}

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
  return useQuery({
    enabled: projectIds.length > 0,
    queryFn: async () => {
      const entries = await Promise.allSettled(
        projectIds.map((projectId) =>
          ProjectsService.readProjectSummary({ project_id: projectId }),
        ),
      )
      const summaryMap: Record<string, ProjectDecisionSummaryPublic> = {}
      entries.forEach((entry, index) => {
        if (entry.status === "fulfilled") {
          summaryMap[projectIds[index]] = entry.value
        }
      })
      return summaryMap
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

export function useDashboardFindingsQuery(projectId: string, enabled: boolean) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: () =>
      FindingsService.readProjectFindings({
        direction: "asc",
        limit: 5,
        offset: 0,
        project_id: projectId,
        sort: "operational",
      }),
    queryKey: workbenchQueryKeys.dashboardFindings(projectId),
    retry: false,
    staleTime: 10_000,
  })
}

export function useDashboardSignalCountsQuery(
  projectId: string,
  enabled: boolean,
) {
  return useQuery({
    enabled: enabled && Boolean(projectId),
    queryFn: async () => {
      const [
        highEpssPage,
        internetFacingCriticalPage,
        epssLowPage,
        epssMediumPage,
        epssHighPage,
        epssCriticalPage,
      ] = await Promise.all([
        FindingsService.readProjectFindings({
          direction: "desc",
          epss_min: 0.7,
          limit: 1,
          offset: 0,
          project_id: projectId,
          sort: "operational",
        }),
        FindingsService.readProjectFindings({
          direction: "desc",
          exposure: "internet-facing",
          limit: 1,
          offset: 0,
          priority: "critical",
          project_id: projectId,
          sort: "operational",
        }),
        FindingsService.readProjectFindings({
          direction: "desc",
          epss_max: 0.25,
          epss_min: 0,
          limit: 1,
          offset: 0,
          project_id: projectId,
          sort: "operational",
        }),
        FindingsService.readProjectFindings({
          direction: "desc",
          epss_max: 0.5,
          epss_min: 0.25,
          limit: 1,
          offset: 0,
          project_id: projectId,
          sort: "operational",
        }),
        FindingsService.readProjectFindings({
          direction: "desc",
          epss_max: 0.7,
          epss_min: 0.5,
          limit: 1,
          offset: 0,
          project_id: projectId,
          sort: "operational",
        }),
        FindingsService.readProjectFindings({
          direction: "desc",
          epss_min: 0.7,
          limit: 1,
          offset: 0,
          project_id: projectId,
          sort: "operational",
        }),
      ])
      return {
        highEpss: highEpssPage.count ?? 0,
        internetFacingCriticals: internetFacingCriticalPage.count ?? 0,
        epssBuckets: {
          low: epssLowPage.count ?? 0,
          medium: epssMediumPage.count ?? 0,
          high: epssHighPage.count ?? 0,
          critical: epssCriticalPage.count ?? 0,
        },
      }
    },
    queryKey: workbenchQueryKeys.dashboardSignalCounts(projectId),
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
      const demoDetail = DEMO_MODE_ENABLED
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
        if (
          caught &&
          typeof caught === "object" &&
          "status" in caught &&
          caught.status === 422
        ) {
          explanationWarning = "Priority explanation unavailable"
        } else {
          throw caught
        }
      }
      return { detail, explanation, explanationWarning }
    },
    queryKey: workbenchQueryKeys.findingDetail(findingId),
    retry: false,
    staleTime: 10_000,
  })
}

export function emptyFindingQueryPage(enabled: boolean) {
  return enabled ? undefined : emptyFindingPage()
}
