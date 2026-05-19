import type {
  AnalysisRunPublic,
  GovernanceRollupPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { EpssBucketCounts } from "@/lib/chart-data"

export const DEMO_PROJECT_ID = "__demo__"

export const DEMO_PROJECT = {
  id: DEMO_PROJECT_ID,
  name: "Demo — Payments Service",
  description: "Sample security posture for demo preview. Not real data.",
  created_at: "2025-01-15T00:00:00Z",
  updated_at: "2025-04-30T00:00:00Z",
} as unknown as ProjectPublic

export const DEMO_SUMMARY = {
  project_id: DEMO_PROJECT_ID,
  finding_count: 136,
  open_finding_count: 78,
  kev_hits: 7,
  epss_hits: 18,
  latest_run_id: "demo00010001",
  latest_run_status: "succeeded",
  counts_by_priority: {
    Critical: 12,
    High: 34,
    Medium: 67,
    Low: 23,
    critical: 12,
    high: 34,
    medium: 67,
    low: 23,
  },
  counts_by_status: {
    open: 78,
    in_review: 12,
    remediating: 8,
    waived: 3,
    accepted: 5,
  },
  provider_degraded: false,
} as unknown as ProjectDecisionSummaryPublic

export const DEMO_EPSS_BUCKETS: EpssBucketCounts = {
  low: 45,
  medium: 38,
  high: 22,
  critical: 13,
}

export const DEMO_SIGNAL_COUNTS = {
  highEpss: 18,
  internetFacingCriticals: 5,
  epssBuckets: DEMO_EPSS_BUCKETS,
}

export const DEMO_PROVIDER_STATUS = {
  status: "ok",
  cache_age_seconds: 3600,
  snapshot_mode: "provider",
  warnings: [],
  last_error: null,
  snapshot: {
    id: "snap-demo",
    locked_provider_data: false,
    selected_sources: ["nvd", "epss", "kev"],
    source_hashes: {},
    source_metadata: {},
  },
} as unknown as ProviderStatusPublic

export const DEMO_RUNS = [
  {
    id: "demo-run-0001",
    project_id: DEMO_PROJECT_ID,
    input_type: "provider",
    status: "succeeded",
    started_at: "2025-04-30T08:00:00Z",
    finished_at: "2025-04-30T08:04:22Z",
  },
  {
    id: "demo-run-0002",
    project_id: DEMO_PROJECT_ID,
    input_type: "provider",
    status: "succeeded",
    started_at: "2025-04-29T08:00:00Z",
    finished_at: "2025-04-29T08:03:58Z",
  },
  {
    id: "demo-run-0003",
    project_id: DEMO_PROJECT_ID,
    input_type: "provider",
    status: "succeeded",
    started_at: "2025-04-28T08:00:00Z",
    finished_at: "2025-04-28T08:05:11Z",
  },
  {
    id: "demo-run-0004",
    project_id: DEMO_PROJECT_ID,
    input_type: "provider",
    status: "failed",
    started_at: "2025-04-27T08:00:00Z",
    finished_at: "2025-04-27T08:01:30Z",
  },
] as unknown as AnalysisRunPublic[]

export const DEMO_TOP_SERVICES = [
  {
    dimension: "service",
    label: "payments-gateway",
    finding_count: 18,
    highest_priority: "Critical",
    risk_score_total: 84.2,
    open_count: 15,
    critical_count: 5,
    high_count: 8,
  },
  {
    dimension: "service",
    label: "vpn-service",
    finding_count: 14,
    highest_priority: "Critical",
    risk_score_total: 71.5,
    open_count: 12,
    critical_count: 4,
    high_count: 6,
  },
  {
    dimension: "service",
    label: "api-gateway",
    finding_count: 22,
    highest_priority: "High",
    risk_score_total: 63.8,
    open_count: 19,
    critical_count: 0,
    high_count: 9,
  },
  {
    dimension: "service",
    label: "platform-infra",
    finding_count: 16,
    highest_priority: "High",
    risk_score_total: 55.1,
    open_count: 13,
    critical_count: 0,
    high_count: 7,
  },
  {
    dimension: "service",
    label: "ci-cd-pipeline",
    finding_count: 9,
    highest_priority: "High",
    risk_score_total: 47.3,
    open_count: 7,
    critical_count: 0,
    high_count: 4,
  },
] as unknown as GovernanceRollupPublic[]
