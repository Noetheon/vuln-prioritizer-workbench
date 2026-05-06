export const workbenchQueryKeys = {
  all: ["workbench"] as const,
  apiTokens: () => [...workbenchQueryKeys.all, "api-tokens"] as const,
  bootstrap: () => [...workbenchQueryKeys.all, "bootstrap"] as const,
  dashboardFindings: (projectId: string) =>
    [...workbenchQueryKeys.all, "dashboard-findings", projectId] as const,
  dashboardSignalCounts: (projectId: string) =>
    [...workbenchQueryKeys.all, "dashboard-signals", projectId] as const,
  findingDetail: (findingId: string | null) =>
    [...workbenchQueryKeys.all, "finding-detail", findingId ?? "none"] as const,
  findings: (params: Record<string, unknown>) =>
    [...workbenchQueryKeys.all, "findings", params] as const,
  projectAttackSummary: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-attack-summary", projectId] as const,
  projectGovernanceRollups: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-governance-rollups", projectId] as const,
  projectRuns: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-runs", projectId] as const,
  projectSummaries: (projectIds: readonly string[]) =>
    [...workbenchQueryKeys.all, "project-summaries", [...projectIds]] as const,
  projectSummary: (projectId: string) =>
    [...workbenchQueryKeys.all, "project-summary", projectId] as const,
  projects: () => [...workbenchQueryKeys.all, "projects"] as const,
  reports: (runId: string) =>
    [...workbenchQueryKeys.all, "reports", runId] as const,
  runDetail: (runId: string) =>
    [...workbenchQueryKeys.all, "run-detail", runId] as const,
  waivers: (projectId: string) =>
    [...workbenchQueryKeys.all, "waivers", projectId] as const,
}
