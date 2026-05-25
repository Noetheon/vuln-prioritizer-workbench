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
  name: "Online Shop Demo Workspace",
  description:
    "Sample Online Shop risk operations review. Local demo data only.",
  created_at: "2026-04-21T12:00:00Z",
  updated_at: "2026-04-29T12:00:00Z",
} as unknown as ProjectPublic

export const DEMO_SUMMARY = {
  project_id: DEMO_PROJECT_ID,
  finding_count: 24,
  open_finding_count: 18,
  kev_hits: 21,
  epss_hits: 24,
  latest_run_id: "demo-run-0001",
  latest_run_status: "succeeded",
  counts_by_priority: {
    Critical: 16,
    High: 7,
    Medium: 1,
    Low: 0,
    critical: 16,
    high: 7,
    medium: 1,
    low: 0,
  },
  counts_by_status: {
    open: 14,
    in_review: 2,
    remediating: 2,
    fixed: 1,
    accepted: 3,
    suppressed: 2,
  },
  provider_degraded: true,
} as unknown as ProjectDecisionSummaryPublic

export const DEMO_EPSS_BUCKETS: EpssBucketCounts = {
  low: 0,
  medium: 0,
  high: 3,
  critical: 21,
}

export const DEMO_SIGNAL_COUNTS = {
  highEpss: 24,
  internetFacingCriticals: 4,
  epssBuckets: DEMO_EPSS_BUCKETS,
}

export const DEMO_PROVIDER_STATUS = {
  status: "degraded",
  cache_age_seconds: 777600,
  last_error: null,
  last_sync: "2026-04-21T12:00:00Z",
  snapshot_mode: "locked-replay",
  warnings: [
    "Locked provider data is reproducible, but EPSS freshness is past the review threshold.",
  ],
  snapshot: {
    id: "online-shop-demo-provider-snapshot-2026-04-21",
    epss_date: "2026-04-23",
    generated_at: "2026-04-21T12:00:00Z",
    kev_catalog_version: "kev-catalog-v2026.04",
    locked_provider_data: true,
    missing: false,
    mode: "locked-replay",
    nvd_last_sync: "2026-04-21T12:00:00Z",
    requested_cves: 7,
    selected_sources: ["nvd", "epss", "kev"],
    source_hashes: {},
    source_metadata: {
      epss: { record_count: 7, source: "FIRST EPSS API" },
      kev: { record_count: 6, source: "CISA KEV catalog" },
      nvd: { record_count: 7, source: "NVD CVE API 2.0" },
    },
    source_path: "data/demo_provider_snapshot.json",
  },
  sources: [
    {
      available: true,
      cache_age_seconds: 777600,
      detail: "Locked NVD replay from demo provider snapshot.",
      last_sync: "2026-04-21T12:00:00Z",
      name: "nvd",
      selected: true,
      stale: false,
      value: "7 records",
    },
    {
      available: true,
      cache_age_seconds: 777600,
      detail: "EPSS replay is reproducible but should be reviewed before sign-off.",
      last_sync: "2026-04-23T00:00:00Z",
      name: "epss",
      selected: true,
      stale: true,
      value: "24 high-EPSS findings",
    },
    {
      available: true,
      cache_age_seconds: 777600,
      detail: "Stored KEV catalog version requires semantic review.",
      last_sync: null,
      name: "kev",
      selected: true,
      stale: false,
      value: "6 KEV-backed CVEs",
    },
  ],
} as unknown as ProviderStatusPublic

export const DEMO_RUNS = [
  {
    id: "demo-run-0001",
    project_id: DEMO_PROJECT_ID,
    input_type: "generic-occurrence-csv",
    status: "succeeded",
    started_at: "2026-04-29T12:00:00Z",
    finished_at: "2026-04-29T12:04:22Z",
    provider_snapshot_id: "online-shop-demo-provider-snapshot-2026-04-21",
  },
  {
    id: "demo-run-0002",
    project_id: DEMO_PROJECT_ID,
    input_type: "generic-occurrence-csv",
    status: "succeeded",
    started_at: "2026-04-28T12:00:00Z",
    finished_at: "2026-04-28T12:03:58Z",
  },
  {
    id: "demo-run-0003",
    project_id: DEMO_PROJECT_ID,
    input_type: "generic-occurrence-csv",
    status: "succeeded",
    started_at: "2026-04-27T12:00:00Z",
    finished_at: "2026-04-27T12:05:11Z",
  },
  {
    id: "demo-run-0004",
    project_id: DEMO_PROJECT_ID,
    input_type: "generic-occurrence-csv",
    status: "failed",
    started_at: "2026-04-26T12:00:00Z",
    finished_at: "2026-04-26T12:01:30Z",
  },
] as unknown as AnalysisRunPublic[]

export const DEMO_TOP_SERVICES = [
  ["payments", 3, "Critical", 27.7, 2, 3, 0],
  ["checkout", 3, "Critical", 24.6, 3, 2, 1],
  ["identity", 3, "Critical", 24.8, 2, 3, 0],
  ["file-transfer", 2, "Critical", 15.2, 1, 1, 1],
  ["catalog", 3, "Critical", 24.2, 2, 2, 1],
  ["edge", 2, "High", 13.8, 1, 0, 2],
].map(([label, findings, priority, risk, open, critical, high]) => ({
  critical_count: critical,
  dimension: "service",
  finding_count: findings,
  high_count: high,
  highest_priority: priority,
  label,
  open_count: open,
  risk_score_total: risk,
})) as unknown as GovernanceRollupPublic[]
