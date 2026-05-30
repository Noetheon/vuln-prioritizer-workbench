import type { QueryClient } from "@tanstack/react-query"

export const workbenchQueryKeys = {
  all: ["workbench"] as const,
  assetFindings: (projectId: string, assetId: string | null) =>
    [
      ...workbenchQueryKeys.assetFindingsRoot(projectId),
      assetId ?? "none",
    ] as const,
  assetFindingsRoot: (projectId: string) =>
    [...workbenchQueryKeys.all, "asset-findings", projectId] as const,
  assets: (
    projectId: string,
    filters: { owner?: string; service?: string } = {},
  ) =>
    [
      ...workbenchQueryKeys.assetsRoot(projectId),
      {
        owner: filters.owner ?? "",
        service: filters.service ?? "",
      },
    ] as const,
  assetsRoot: (projectId: string) =>
    [...workbenchQueryKeys.all, "assets", projectId] as const,
  providerStatus: () => [...workbenchQueryKeys.all, "provider-status"] as const,
  capabilities: () => [...workbenchQueryKeys.all, "capabilities"] as const,
  demoWorkspace: () => [...workbenchQueryKeys.all, "demo-workspace"] as const,
  projectDashboard: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-dashboard", projectId] as const,
  findingDetail: (findingId: string | null) =>
    [...workbenchQueryKeys.all, "finding-detail", findingId ?? "none"] as const,
  findingsRoot: () => [...workbenchQueryKeys.all, "findings"] as const,
  findings: (params: Record<string, unknown>) =>
    [...workbenchQueryKeys.findingsRoot(), params] as const,
  projectAttackSummary: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-attack-summary", projectId] as const,
  projectGovernanceRollups: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-governance-rollups", projectId] as const,
  projectSummariesRoot: () =>
    [...workbenchQueryKeys.all, "project-summaries"] as const,
  projectRuns: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-runs", projectId] as const,
  projectSummaries: (projectIds: readonly string[]) =>
    [...workbenchQueryKeys.projectSummariesRoot(), [...projectIds]] as const,
  projectSummaryRoot: () =>
    [...workbenchQueryKeys.all, "project-summary"] as const,
  projectSummary: (projectId: string) =>
    [...workbenchQueryKeys.projectSummaryRoot(), projectId] as const,
  projects: () => [...workbenchQueryKeys.all, "projects"] as const,
  reportsRoot: () => [...workbenchQueryKeys.all, "reports"] as const,
  reports: (runId: string) =>
    [...workbenchQueryKeys.reportsRoot(), runId] as const,
  runDetail: (runId: string) =>
    [...workbenchQueryKeys.all, "run-detail", runId] as const,
  status: () => [...workbenchQueryKeys.all, "status"] as const,
  waivers: (projectId: string) =>
    [...workbenchQueryKeys.all, "waivers", projectId] as const,
}

type WorkbenchQueryInvalidator = Pick<QueryClient, "invalidateQueries">

export async function invalidateWorkbenchProjectQueries(
  queryClient: WorkbenchQueryInvalidator,
) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: workbenchQueryKeys.projects() }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.demoWorkspace(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectSummariesRoot(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectSummaryRoot(),
    }),
  ])
}

export async function invalidateProjectScopedWorkbenchQueries(
  queryClient: WorkbenchQueryInvalidator,
  projectId: string,
) {
  if (!projectId) {
    return
  }

  await Promise.all([
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectSummary(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectDashboard(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectSummariesRoot(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectRuns(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.findingsRoot(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectGovernanceRollups(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.waivers(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.assetsRoot(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.assetFindingsRoot(projectId),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.reportsRoot(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.demoWorkspace(),
    }),
    queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.providerStatus(),
    }),
  ])
}
