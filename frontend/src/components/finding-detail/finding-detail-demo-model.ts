import type { FindingDetailPublic, FindingExplanationPublic } from "@/api-client"
import { stringValue } from "@/lib/app-errors"
import {
  DEMO_FINDING_ATTACK_CONTEXTS,
  DEMO_FINDINGS,
  DEMO_PROJECT,
  DEMO_WAIVERS,
} from "@/lib/demo-data"
import { formatLabel as labelize } from "@/lib/ui-copy"

import {
  findingRecommendedAction,
  findingWhyText,
} from "./finding-detail-shared"

export function demoFindingDetailForId(findingId: string) {
  const demoFinding = DEMO_FINDINGS.find((finding) => finding.id === findingId)
  if (!demoFinding) {
    return null
  }
  const createdAt = demoFinding.created_at ?? "2025-04-01T00:00:00Z"
  const lastSeenAt = demoFinding.last_seen_at ?? createdAt
  const waiver = DEMO_WAIVERS.find(
    (item) =>
      item.finding_id === demoFinding.id ||
      (item.cve_id === demoFinding.cve_id &&
        item.asset_key === demoFinding.asset_key),
  )
  const vexStatus = demoFinding.suppressed_by_vex
    ? "not_affected"
    : demoFinding.status === "fixed"
      ? "fixed"
      : demoFinding.under_investigation
        ? "under_investigation"
        : ""
  return {
    ...demoFinding,
    asset_id: demoFinding.asset_id ?? null,
    component_id: demoFinding.component_id ?? null,
    created_at: createdAt,
    data_quality_json: {
      confidence: "Demo Preview",
      flags: [
        {
          code: "demo_preview",
          message:
            "Sample finding detail used only when no real project data is available.",
          severity: "info",
          source: "demo",
        },
      ],
    },
    evidence_json: {
      input_source: "Demo Preview sample queue",
      scanner: "Demo import",
      ...(waiver
        ? {
            waiver: {
              waiver_approval_ref: waiver.approval_ref,
              waiver_days_remaining: waiver.days_remaining,
              waiver_expires_on: waiver.expires_at,
              waiver_id: waiver.id,
              waiver_matched_scope: waiver.asset_key ?? waiver.service,
              waiver_owner: waiver.owner,
              waiver_reason: waiver.reason,
              waiver_review_on: waiver.review_at,
              waiver_scope: waiver.asset_key ?? waiver.service,
              waiver_status: waiver.status,
              waiver_ticket_url: waiver.ticket_url,
            },
          }
        : {}),
    },
    explanation_json: waiver
      ? {
          waiver_approval_ref: waiver.approval_ref,
          waiver_days_remaining: waiver.days_remaining,
          waiver_expires_on: waiver.expires_at,
          waiver_id: waiver.id,
          waiver_matched_scope: waiver.asset_key ?? waiver.service,
          waiver_owner: waiver.owner,
          waiver_reason: waiver.reason,
          waiver_review_on: waiver.review_at,
          waiver_scope: waiver.asset_key ?? waiver.service,
          waiver_status: waiver.status,
          waiver_ticket_url: waiver.ticket_url,
        }
      : {},
    first_seen_at: demoFinding.first_seen_at ?? createdAt,
    last_seen_at: lastSeenAt,
    attack_context: DEMO_FINDING_ATTACK_CONTEXTS[demoFinding.id] ?? null,
    occurrences: [
      {
        analysis_run_id: "demo-run-0001",
        asset_business_service: demoFinding.business_service,
        asset_exposure: demoFinding.exposure,
        asset_owner: demoFinding.owner,
        asset_ref:
          demoFinding.asset_name ??
          demoFinding.asset_key ??
          demoFinding.business_service,
        component_name: demoFinding.component_name,
        component_version: demoFinding.component_version,
        created_at: createdAt,
        fix_version: stringValue(demoFinding.recommended_action),
        id: `${demoFinding.id}-occurrence-1`,
        purl: demoFinding.component_purl,
        raw_severity: labelize(demoFinding.priority),
        scanner: "Demo import",
        source: "Demo Preview",
        source_format: "Sample finding",
        source_record_id: demoFinding.cve_id,
        target_kind: "service",
        target_ref: demoFinding.business_service,
        vex_action_statement: demoFinding.under_investigation
          ? "Confirm exposure before closing or escalating."
          : "",
        vex_justification: demoFinding.suppressed_by_vex
          ? "vulnerable_code_not_in_execute_path"
          : "",
        vex_match_type: vexStatus ? "purl" : "",
        vex_status: vexStatus,
      },
    ],
    project_id: DEMO_PROJECT.id,
    updated_at: demoFinding.updated_at ?? lastSeenAt,
    vulnerability_id: demoFinding.vulnerability_id ?? demoFinding.cve_id,
  } as FindingDetailPublic
}

export function demoFindingExplanationForDetail(
  finding: FindingDetailPublic,
): FindingExplanationPublic {
  return {
    cve_id: finding.cve_id,
    data_quality_confidence: "Demo Preview",
    decision_explanation: {
      human_readable: findingWhyText(finding, null),
    },
    decision_guidance: {
      recommended_action: findingRecommendedAction(finding, null),
    },
    finding_id: finding.id,
    priority: finding.priority ?? "medium",
    priority_rank: finding.priority_rank ?? 0,
    project_id: finding.project_id,
    provider_evidence: {
      demo_preview: true,
      epss: finding.epss,
      cvss_base_score: finding.cvss_base_score,
      in_kev: finding.in_kev,
    },
    rationale: finding.rationale,
    recommended_action: finding.recommended_action,
    risk_score: finding.risk_score,
  }
}

export function isDemoFindingDetail(finding: FindingDetailPublic | null) {
  return Boolean(
    finding &&
      (finding.project_id === DEMO_PROJECT.id ||
        finding.id.startsWith("demo-")),
  )
}
