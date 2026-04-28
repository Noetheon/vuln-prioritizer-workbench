import { useQuery } from "@tanstack/react-query";

import { apiGet } from "../api/client";
import type {
  AnalysisRun,
  AnalysisRunArtifactsResponse,
  ApiTokensListResponse,
  ArtifactsListResponse,
  Asset,
  CoverageGapResponse,
  DetectionControl,
  Finding,
  FindingAttackContextResponse,
  FindingExplainResponse,
  FindingsListResponse,
  GovernanceRollupsResponse,
  ListResponse,
  Project,
  ProjectConfigItemResponse,
  ProjectDashboardResponse,
  ProviderUpdateJob,
  ProviderStatusResponse,
  TechniqueDetailResponse,
  TopTechniquesResponse,
  VulnerabilityDetailResponse,
  Waiver,
  WorkbenchArtifactOptionsResponse,
  WorkbenchBootstrapResponse
} from "../api/types";

export interface FindingFilters {
  q?: string;
  priority?: string;
  status?: string;
  kev?: string;
  owner?: string;
  service?: string;
  min_epss?: string;
  min_cvss?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export function useProjects() {
  return useQuery({
    queryKey: ["projects"],
    queryFn: () => apiGet<ListResponse<Project>>("/api/projects")
  });
}

export function useWorkbenchBootstrap() {
  return useQuery({
    queryKey: ["workbench", "bootstrap"],
    queryFn: () => apiGet<WorkbenchBootstrapResponse>("/api/workbench/bootstrap")
  });
}

export function useWorkbenchArtifacts() {
  return useQuery({
    queryKey: ["workbench", "artifacts"],
    queryFn: () => apiGet<WorkbenchArtifactOptionsResponse>("/api/workbench/artifacts")
  });
}

export function useProject(projectId: string | undefined) {
  return useQuery({
    queryKey: ["project", projectId],
    queryFn: () => apiGet<Project>(`/api/projects/${projectId}`),
    enabled: Boolean(projectId)
  });
}

export function useProjectFindings(projectId: string | undefined, filters: FindingFilters = {}) {
  return useQuery({
    queryKey: ["findings", projectId, filters],
    queryFn: () => apiGet<FindingsListResponse>(`/api/projects/${projectId}/findings${queryString(filters)}`),
    enabled: Boolean(projectId)
  });
}

export function useProjectDashboard(projectId: string | undefined) {
  return useQuery({
    queryKey: ["dashboard", projectId],
    queryFn: () => apiGet<ProjectDashboardResponse>(`/api/projects/${projectId}/dashboard`),
    enabled: Boolean(projectId)
  });
}

export function useFinding(findingId: string | undefined) {
  return useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => apiGet<Finding>(`/api/findings/${findingId}`),
    enabled: Boolean(findingId)
  });
}

export function useFindingAttackContext(findingId: string | undefined) {
  return useQuery({
    queryKey: ["finding-attack", findingId],
    queryFn: () => apiGet<FindingAttackContextResponse>(`/api/findings/${findingId}/ttps`),
    enabled: Boolean(findingId),
    retry: false
  });
}

export function useFindingExplain(findingId: string | undefined) {
  return useQuery({
    queryKey: ["finding-explain", findingId],
    queryFn: () => apiGet<FindingExplainResponse>(`/api/findings/${findingId}/explain`),
    enabled: Boolean(findingId)
  });
}

export function useProjectRuns(projectId: string | undefined) {
  return useQuery({
    queryKey: ["runs", projectId],
    queryFn: () => apiGet<ListResponse<AnalysisRun>>(`/api/projects/${projectId}/runs`),
    enabled: Boolean(projectId)
  });
}

export function useRunArtifacts(runId: string | undefined) {
  return useQuery({
    queryKey: ["run-artifacts", runId],
    queryFn: () => apiGet<AnalysisRunArtifactsResponse>(`/api/analysis-runs/${runId}/artifacts`),
    enabled: Boolean(runId)
  });
}

export function useGeneratedArtifacts(limit = 100, offset = 0) {
  return useQuery({
    queryKey: ["generated-artifacts", limit, offset],
    queryFn: () => apiGet<ArtifactsListResponse>(`/api/workbench/generated-artifacts?limit=${limit}&offset=${offset}`)
  });
}

export function useProjectAssets(projectId: string | undefined) {
  return useQuery({
    queryKey: ["assets", projectId],
    queryFn: () => apiGet<ListResponse<Asset>>(`/api/projects/${projectId}/assets`),
    enabled: Boolean(projectId)
  });
}

export function useProjectWaivers(projectId: string | undefined) {
  return useQuery({
    queryKey: ["waivers", projectId],
    queryFn: () => apiGet<ListResponse<Waiver>>(`/api/projects/${projectId}/waivers`),
    enabled: Boolean(projectId)
  });
}

export function useDetectionControls(projectId: string | undefined) {
  return useQuery({
    queryKey: ["detection-controls", projectId],
    queryFn: () => apiGet<ListResponse<DetectionControl>>(`/api/projects/${projectId}/detection-controls`),
    enabled: Boolean(projectId)
  });
}

export function useCoverageGaps(projectId: string | undefined) {
  return useQuery({
    queryKey: ["coverage-gaps", projectId],
    queryFn: () => apiGet<CoverageGapResponse>(`/api/projects/${projectId}/attack/coverage-gaps`),
    enabled: Boolean(projectId)
  });
}

export function useTechniqueDetail(projectId: string | undefined, techniqueId: string | undefined) {
  return useQuery({
    queryKey: ["attack", "technique-detail", projectId, techniqueId],
    queryFn: () =>
      apiGet<TechniqueDetailResponse>(
        `/api/projects/${projectId}/attack/techniques/${encodeURIComponent(techniqueId ?? "")}`
      ),
    enabled: Boolean(projectId && techniqueId)
  });
}

export function useProviderStatus() {
  return useQuery({
    queryKey: ["providers", "status"],
    queryFn: () => apiGet<ProviderStatusResponse>("/api/providers/status")
  });
}

export function useProviderUpdateJobs() {
  return useQuery({
    queryKey: ["providers", "update-jobs"],
    queryFn: () => apiGet<ListResponse<ProviderUpdateJob>>("/api/providers/update-jobs")
  });
}

export function useApiTokens() {
  return useQuery({
    queryKey: ["tokens"],
    queryFn: () => apiGet<ApiTokensListResponse>("/api/tokens")
  });
}

export function useProjectConfig(projectId: string | undefined) {
  return useQuery({
    queryKey: ["project-config", projectId],
    queryFn: () => apiGet<ProjectConfigItemResponse>(`/api/projects/${projectId}/settings/config`),
    enabled: Boolean(projectId)
  });
}

export function useProjectVulnerability(projectId: string | undefined, cveId: string) {
  const normalized = cveId.trim().toUpperCase();
  return useQuery({
    queryKey: ["vulnerability", projectId, normalized],
    queryFn: () =>
      apiGet<VulnerabilityDetailResponse>(
        `/api/projects/${projectId}/vulnerabilities/${encodeURIComponent(normalized)}`
      ),
    enabled: Boolean(projectId && normalized)
  });
}

export function useTopTechniques(projectId: string | undefined, limit = 8) {
  return useQuery({
    queryKey: ["attack", "top-techniques", projectId, limit],
    queryFn: () => apiGet<TopTechniquesResponse>(`/api/projects/${projectId}/attack/top-techniques?limit=${limit}`),
    enabled: Boolean(projectId)
  });
}

export function useGovernanceRollups(projectId: string | undefined, limit = 10) {
  return useQuery({
    queryKey: ["governance", projectId, limit],
    queryFn: () => apiGet<GovernanceRollupsResponse>(`/api/projects/${projectId}/governance/rollups?limit=${limit}`),
    enabled: Boolean(projectId)
  });
}

function queryString(filters: FindingFilters): string {
  const params = new URLSearchParams();
  for (const [key, rawValue] of Object.entries(filters)) {
    if (rawValue === undefined || rawValue === null || rawValue === "") {
      continue;
    }
    params.set(key, String(rawValue));
  }
  const value = params.toString();
  return value ? `?${value}` : "";
}
