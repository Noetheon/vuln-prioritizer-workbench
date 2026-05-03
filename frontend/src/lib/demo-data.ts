/**
 * Demo preview data – displayed only when no real project is connected.
 *
 * This module is CLEARLY LABELED in the UI and never silently replaces live
 * production API data. It exists solely so the Dashboard is evaluable during
 * local development without a seeded backend.
 *
 * All IDs are prefixed "__demo__" so accidental persistence is impossible.
 */

import type {
  AnalysisRunPublic,
  FindingAttackContextDetailPublic,
  FindingPublic,
  GovernanceRollupPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { EpssBucketCounts } from "@/lib/chart-data"

export const DEMO_PROJECT_ID = "__demo__"

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

export const DEMO_PROJECT = {
  id: DEMO_PROJECT_ID,
  name: "Demo — Payments Service",
  description: "Sample security posture for demo preview. Not real data.",
  created_at: "2025-01-15T00:00:00Z",
  updated_at: "2025-04-30T00:00:00Z",
} as unknown as ProjectPublic

// ---------------------------------------------------------------------------
// Decision Summary
// ---------------------------------------------------------------------------

export const DEMO_SUMMARY = {
  project_id: DEMO_PROJECT_ID,
  finding_count: 136,
  open_finding_count: 78,
  kev_hits: 7,
  epss_hits: 18,
  latest_run_id: "demo00010001",
  latest_run_status: "succeeded",
  counts_by_priority: {
    Critical: 12, High: 34, Medium: 67, Low: 23,
    critical: 12, high: 34, medium: 67, low: 23,
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

// ---------------------------------------------------------------------------
// Signal counts
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Provider status
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Analysis runs
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Top services by risk
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Findings (top remediation queue)
// ---------------------------------------------------------------------------

export const DEMO_FINDINGS = [
  {
    id: "demo-f1",
    asset_id: "demo-asset-1",
    component_id: "demo-comp-1",
    cve_id: "CVE-2024-3400",
    priority: "critical",
    risk_score: 9.8,
    epss: 0.92,
    cvss_base_score: 10.0,
    in_kev: true,
    status: "open",
    component_name: "PAN-OS",
    component_purl: "pkg:rpm/panos@11.1.0",
    business_service: "payments-gateway",
    owner: "infra-team",
    exposure: "internet_facing",
    created_at: "2025-04-01T00:00:00Z",
    last_seen_at: "2025-04-30T10:00:00Z",
    rationale:
      "Exploited in the wild, CISA KEV entry, active ransomware campaigns targeting PAN-OS.",
    recommended_action: "Patch immediately to PAN-OS 11.1.2-h3.",
  },
  {
    id: "demo-f2",
    asset_id: "demo-asset-2",
    component_id: "demo-comp-2",
    cve_id: "CVE-2024-21887",
    priority: "critical",
    risk_score: 9.1,
    epss: 0.88,
    cvss_base_score: 9.1,
    in_kev: true,
    status: "open",
    component_name: "Ivanti Connect Secure",
    component_purl: "pkg:generic/ivanti-connect@22.3.3",
    business_service: "vpn-service",
    owner: "network-team",
    exposure: "internet_facing",
    created_at: "2025-04-02T00:00:00Z",
    last_seen_at: "2025-04-29T09:00:00Z",
    rationale:
      "Command injection in web component, mass exploitation observed.",
    recommended_action:
      "Apply Ivanti patch and run factory reset per vendor advisory.",
  },
  {
    id: "demo-f3",
    asset_id: "demo-asset-3",
    component_id: "demo-comp-3",
    cve_id: "CVE-2024-1709",
    priority: "critical",
    risk_score: 9.4,
    epss: 0.95,
    cvss_base_score: 10.0,
    in_kev: false,
    status: "in_review",
    component_name: "ConnectWise ScreenConnect",
    component_purl: "pkg:generic/screenconnect@23.9.7",
    business_service: "internal-tools",
    owner: "it-team",
    exposure: "internal",
    created_at: "2025-04-03T00:00:00Z",
    last_seen_at: "2025-04-27T11:00:00Z",
    rationale:
      "Auth bypass with EPSS > 0.95 — exploitation probability is very high.",
    recommended_action: "Upgrade to ScreenConnect 23.9.8 immediately.",
  },
  {
    id: "demo-f4",
    asset_id: "demo-asset-4",
    component_id: "demo-comp-4",
    cve_id: "CVE-2023-4966",
    priority: "critical",
    risk_score: 8.9,
    epss: 0.87,
    cvss_base_score: 9.4,
    in_kev: true,
    status: "open",
    component_name: "Citrix NetScaler",
    component_purl: "pkg:generic/netscaler@13.1",
    business_service: "load-balancer",
    owner: "platform-team",
    exposure: "internet_facing",
    created_at: "2025-04-04T00:00:00Z",
    last_seen_at: "2025-04-26T08:00:00Z",
    rationale:
      "Citrix Bleed — session token leak, KEV entry, active exploitation.",
    recommended_action: "Apply Citrix security bulletin CTX579459.",
  },
  {
    id: "demo-f5",
    asset_id: "demo-asset-5",
    component_id: "demo-comp-5",
    cve_id: "CVE-2023-44487",
    priority: "high",
    risk_score: 7.5,
    epss: 0.71,
    cvss_base_score: 7.5,
    in_kev: true,
    status: "open",
    component_name: "nginx",
    component_purl: "pkg:deb/nginx@1.18.0",
    business_service: "api-gateway",
    owner: "platform-team",
    exposure: "internet_facing",
    created_at: "2025-04-05T00:00:00Z",
    last_seen_at: "2025-04-28T14:00:00Z",
    rationale: "HTTP/2 Rapid Reset DoS, actively exploited.",
    recommended_action: "Upgrade nginx to 1.24.0 or later.",
  },
  {
    id: "demo-f6",
    asset_id: "demo-asset-6",
    component_id: "demo-comp-6",
    cve_id: "CVE-2024-27198",
    priority: "high",
    risk_score: 7.8,
    epss: 0.73,
    cvss_base_score: 9.8,
    in_kev: false,
    status: "open",
    component_name: "JetBrains TeamCity",
    component_purl: "pkg:generic/teamcity@2023.11.3",
    business_service: "ci-cd-pipeline",
    owner: "devops-team",
    exposure: "internal",
    created_at: "2025-04-06T00:00:00Z",
    last_seen_at: "2025-04-25T16:00:00Z",
    rationale:
      "Auth bypass in TeamCity server, high EPSS exploitation signal.",
    recommended_action: "Upgrade to TeamCity 2023.11.4.",
  },
  {
    id: "demo-f7",
    asset_id: "demo-asset-7",
    component_id: "demo-comp-7",
    cve_id: "CVE-2023-46805",
    priority: "high",
    risk_score: 6.9,
    epss: 0.64,
    cvss_base_score: 8.2,
    in_kev: true,
    status: "remediating",
    component_name: "Ivanti Policy Secure",
    component_purl: "pkg:generic/ivanti-policy@22.3",
    business_service: "vpn-service",
    owner: "network-team",
    exposure: "internet_facing",
    created_at: "2025-04-07T00:00:00Z",
    last_seen_at: "2025-04-24T10:00:00Z",
    rationale:
      "KEV entry, pairs with CVE-2024-21887 for chained exploitation.",
    recommended_action:
      "Remediation in progress — verify patch application.",
  },
  {
    id: "demo-f8",
    asset_id: "demo-asset-8",
    component_id: "demo-comp-8",
    cve_id: "CVE-2024-3094",
    priority: "high",
    risk_score: 6.5,
    epss: 0.61,
    cvss_base_score: 10.0,
    in_kev: false,
    status: "open",
    component_name: "xz-utils",
    component_purl: "pkg:deb/xz-utils@5.6.0",
    business_service: "platform-infra",
    owner: "platform-team",
    exposure: "internal",
    created_at: "2025-04-08T00:00:00Z",
    last_seen_at: "2025-04-23T12:00:00Z",
    rationale: "XZ backdoor in liblzma — supply chain compromise.",
    recommended_action:
      "Downgrade to xz-utils 5.4.x and rebuild affected containers.",
  },
  {
    id: "demo-f9",
    asset_id: "demo-asset-9",
    component_id: "demo-comp-9",
    cve_id: "CVE-2024-21413",
    priority: "medium",
    risk_score: 5.2,
    epss: 0.42,
    cvss_base_score: 9.8,
    in_kev: false,
    status: "open",
    component_name: "Microsoft Outlook",
    component_purl: "pkg:generic/outlook@2021",
    business_service: "collaboration",
    owner: "it-team",
    exposure: "internal",
    created_at: "2025-04-09T00:00:00Z",
    last_seen_at: "2025-04-22T09:00:00Z",
    rationale:
      "Moniker link bypass — critical CVSS but lower operational EPSS.",
    recommended_action: "Apply February 2024 Patch Tuesday update.",
  },
  {
    id: "demo-f10",
    asset_id: "demo-asset-10",
    component_id: "demo-comp-10",
    cve_id: "CVE-2023-36884",
    priority: "medium",
    risk_score: 4.8,
    epss: 0.38,
    cvss_base_score: 8.3,
    in_kev: true,
    status: "waived",
    component_name: "Microsoft Office",
    component_purl: "pkg:generic/office@2021",
    business_service: "collaboration",
    owner: "it-team",
    exposure: "internal",
    created_at: "2025-04-10T00:00:00Z",
    last_seen_at: "2025-04-21T14:00:00Z",
    rationale:
      "Office HTML injection — waived pending compensating control review.",
    recommended_action: "Apply KB5028185 when waiver expires.",
  },
] as unknown as FindingPublic[]

// ---------------------------------------------------------------------------
// Reports (demo history rows – used only when no real project is connected)
// ---------------------------------------------------------------------------

export const DEMO_REPORTS = [
  {
    id: "__demo__report-001",
    analysis_run_id: "demo-run-0001",
    content_type: "text/html",
    created_at: "2025-04-30T08:12:00Z",
    download_url: "#demo-download",
    filename: "vpw-evidence-2025-04-30-executive.html",
    format: "html",
    kind: "report",
    project_id: DEMO_PROJECT_ID,
    sha256: "demo-only-not-a-real-checksum",
    size_bytes: 84231,
    metadata_json: undefined,
  },
  {
    id: "__demo__report-002",
    analysis_run_id: "demo-run-0001",
    content_type: "text/markdown",
    created_at: "2025-04-30T08:11:00Z",
    download_url: "#demo-download",
    filename: "vpw-evidence-2025-04-30-technical.md",
    format: "markdown",
    kind: "report",
    project_id: DEMO_PROJECT_ID,
    sha256: "demo-only-not-a-real-checksum",
    size_bytes: 32109,
    metadata_json: undefined,
  },
  {
    id: "__demo__report-003",
    analysis_run_id: "demo-run-0001",
    content_type: "application/json",
    created_at: "2025-04-30T08:11:30Z",
    download_url: "#demo-download",
    filename: "vpw-evidence-2025-04-30-findings.json",
    format: "json",
    kind: "report",
    project_id: DEMO_PROJECT_ID,
    sha256: "demo-only-not-a-real-checksum",
    size_bytes: 156023,
    metadata_json: undefined,
  },
  {
    id: "__demo__report-004",
    analysis_run_id: "demo-run-0001",
    content_type: "application/zip",
    created_at: "2025-04-30T08:13:00Z",
    download_url: "#demo-download",
    filename: "vpw-evidence-bundle-2025-04-30.zip",
    format: "zip",
    kind: "report",
    project_id: DEMO_PROJECT_ID,
    sha256: "demo-only-not-a-real-checksum",
    size_bytes: 312456,
    metadata_json: undefined,
  },
]

export const DEMO_FINDING_ATTACK_CONTEXTS: Record<
  string,
  FindingAttackContextDetailPublic
> = {
  "demo-f1": {
    attack_relevance: "defensive_prioritization",
    confidence: "high",
    defensive_note:
      "Partial / unknown coverage. Validate web, proxy, WAF, EDR, and application telemetry, then document detection coverage and residual risk before closure.",
    low_confidence: false,
    mapped: true,
    mappings: [
      {
        confidence: "high",
        defensive_note:
          "Patch or mitigate the vulnerable service.\nRestrict exposure while remediation is in progress.\nValidate web, proxy, WAF, EDR, and application telemetry.\nDocument detection coverage and residual risk.",
        mapping_type: "curated_demo",
        rationale:
          "This finding affects an internet-facing service and represents a public-facing application exploitation risk. The mapping is used for defensive prioritization, detection planning, and remediation context.",
        references: ["Local curated demo mapping"],
        review_status: "curated_demo",
        source: "Local curated demo mapping",
        tactics: ["Initial Access"],
        technique_id: "T1190",
        technique_name: "Exploit Public-Facing Application",
      },
    ],
    rationale:
      "This finding affects an internet-facing service and represents a public-facing application exploitation risk. The mapping is used for defensive prioritization, detection planning, and remediation context.",
    review_status: "curated_demo",
    source: "Local curated demo mapping",
    tactics: ["Initial Access"],
    technique_ids: ["T1190"],
    techniques: [
      {
        confidence: "high",
        defensive_note:
          "Patch or mitigate the vulnerable service.\nRestrict exposure while remediation is in progress.\nValidate web, proxy, WAF, EDR, and application telemetry.\nDocument detection coverage and residual risk.",
        name: "Exploit Public-Facing Application",
        rationale:
          "This finding affects an internet-facing service and represents a public-facing application exploitation risk. The mapping is used for defensive prioritization, detection planning, and remediation context.",
        review_status: "curated_demo",
        source: "Local curated demo mapping",
        tactics: ["Initial Access"],
        technique_id: "T1190",
        url: "https://attack.mitre.org/techniques/T1190/",
      },
    ],
  },
}
