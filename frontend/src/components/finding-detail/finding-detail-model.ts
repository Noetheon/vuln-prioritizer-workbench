import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingOccurrencePublic,
  FindingPriority,
} from "@/api-client"
import {
  arrayRecords,
  joinedValues,
  objectRecord,
  stringValue,
} from "@/lib/app-errors"
import {
  DEMO_FINDING_ATTACK_CONTEXTS,
  DEMO_FINDINGS,
  DEMO_PROJECT,
} from "@/lib/demo-data"
import { formatEpss, formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"

export type FindingAttackContext = NonNullable<
  FindingDetailPublic["attack_context"]
>

export type FindingDecisionReason = {
  detail: string
  label: string
  tone: "critical" | "warning" | "info" | "positive"
}

export type FindingDetailRow = {
  detail?: string
  label: string
  value: string
}

export type FindingOccurrenceRow = Partial<FindingOccurrencePublic> &
  Record<string, unknown>

const decisionReasonCopy: Record<string, { label: string; detail: string }> = {
  "asset.context": {
    detail: "Asset context influences operational priority.",
    label: "Asset context",
  },
  "asset.context_unknown": {
    detail:
      "Asset context is missing and must be validated before final scheduling.",
    label: "Asset context unknown",
  },
  "operational.score": {
    detail: "Combined signals determine the operational remediation score.",
    label: "Operational score",
  },
  "priority.critical.epss_cvss": {
    detail: "EPSS and CVSS together indicate critical remediation urgency.",
    label: "Critical EPSS and CVSS",
  },
  "priority.high.cvss": {
    detail: "CVSS indicates high impact severity.",
    label: "High CVSS",
  },
  "priority.high.epss": {
    detail: "EPSS indicates elevated exploitation probability.",
    label: "High EPSS",
  },
  "priority.kev.known_exploited": {
    detail: "Known exploited vulnerability signal is present.",
    label: "Known exploited vulnerability",
  },
  "priority.medium.cvss": {
    detail: "CVSS contributes meaningful impact severity.",
    label: "Medium CVSS signal",
  },
  "priority.medium.epss": {
    detail: "EPSS contributes exploitation probability context.",
    label: "Medium EPSS signal",
  },
}

export function humanizeDecisionReasonText(value: string | null | undefined) {
  if (!value) {
    return value
  }
  return Object.entries(decisionReasonCopy).reduce(
    (text, [code, copy]) =>
      text.replaceAll(code, copy.detail.replace(/\.$/, "")),
    value,
  )
}

function decisionReasonLabel(value: string | null | undefined) {
  if (!value) {
    return "Reason"
  }
  return decisionReasonCopy[value]?.label ?? labelize(value)
}

function decisionReasonDetail(
  code: string | null | undefined,
  detail: string | null | undefined,
) {
  return (
    humanizeDecisionReasonText(detail) ?? decisionReasonCopy[code ?? ""]?.detail
  )
}

export function findingOccurrenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
): FindingOccurrenceRow[] {
  if (finding?.occurrences?.length) {
    return finding.occurrences
  }
  const explanationPayload = objectRecord(explanation?.explanation)
  const explanationProvenance = objectRecord(explanationPayload.provenance)
  const findingProvenance = objectRecord(
    objectRecord(finding?.explanation_json).provenance,
  )
  return arrayRecords(
    explanationProvenance.occurrences ?? findingProvenance.occurrences,
  ).map((occurrence, index) => ({
    ...occurrence,
    id: stringValue(occurrence.id) ?? `occurrence-${index + 1}`,
  }))
}

export function findingWhyText(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const fallback = "No priority explanation has been recorded for this finding."
  return (
    humanizeDecisionReasonText(
      stringValue(decisionExplanation.human_readable) ??
        stringValue(decisionExplanation.summary) ??
        explanation?.rationale ??
        finding?.rationale ??
        fallback,
    ) ?? fallback
  )
}

export function findingRecommendedAction(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionGuidance = objectRecord(explanation?.decision_guidance)
  return (
    stringValue(decisionGuidance.recommended_action) ??
    explanation?.recommended_action ??
    finding?.recommended_action ??
    "No recommended action has been recorded."
  )
}

export function findingComponentDetailLabel(
  finding: FindingDetailPublic | null,
) {
  if (!finding) {
    return "N.A."
  }
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

export function findingAssetServiceDetailLabel(
  finding: FindingDetailPublic | null,
) {
  if (!finding) {
    return "N.A."
  }
  return joinedValues([
    finding.business_service,
    finding.asset_name,
    finding.asset_key,
    finding.asset_target_ref,
  ])
}

export function findingOwnerDetailLabel(
  finding: FindingDetailPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
) {
  return (
    finding?.owner ?? stringValue(occurrences[0]?.asset_owner) ?? "Unassigned"
  )
}

export function findingSlaLabel(priority: FindingPriority | undefined) {
  switch (priority) {
    case "critical":
      return "24 hours"
    case "high":
      return "7 days"
    case "medium":
      return "30 days"
    case "low":
      return "90 days"
    default:
      return "Define during triage"
  }
}

export function findingNextStepLabel(finding: FindingDetailPublic | null) {
  switch (finding?.status) {
    case "open":
      return "Assign remediation work and start fix validation."
    case "in_review":
      return "Complete technical review and confirm the remediation path."
    case "remediating":
      return "Verify the fix, then update evidence and status."
    case "fixed":
      return "Confirm scanner closure and keep evidence for reporting."
    case "accepted":
      return "Track accepted risk until the next review date."
    case "suppressed":
      return "Verify the VEX or suppression scope still applies."
    default:
      return "Confirm ownership and record the next remediation step."
  }
}

function findingAssetLabel(finding: FindingDetailPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

function isInternetFacingExposure(value: string | null | undefined) {
  return value ? value.toLowerCase().includes("internet") : false
}

function isProductionEnvironment(value: string | null | undefined) {
  return value ? /\bprod(uction)?\b/i.test(value.replaceAll("_", " ")) : false
}

export function findingDecisionReasonRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  attackContext: FindingAttackContext | null,
) {
  const rows: FindingDecisionReason[] = []

  if (finding?.in_kev) {
    rows.push({
      detail:
        "CISA KEV is recorded for this CVE, so exploitation is a confirmed prioritization signal.",
      label: "CISA KEV listed",
      tone: "critical",
    })
  }

  if (finding?.epss !== null && finding?.epss !== undefined) {
    rows.push({
      detail:
        finding.epss >= 0.7
          ? `${formatEpss(finding.epss)} EPSS indicates elevated exploitation probability.`
          : `${formatEpss(finding.epss)} EPSS is recorded for the decision model.`,
      label: finding.epss >= 0.7 ? "High EPSS" : "EPSS recorded",
      tone: finding.epss >= 0.7 ? "warning" : "info",
    })
  }

  if (
    finding?.cvss_base_score !== null &&
    finding?.cvss_base_score !== undefined
  ) {
    rows.push({
      detail:
        finding.cvss_base_score >= 9
          ? `CVSS ${formatNullableNumber(finding.cvss_base_score)} is critical impact severity.`
          : `CVSS ${formatNullableNumber(finding.cvss_base_score)} contributes to the risk score.`,
      label: finding.cvss_base_score >= 9 ? "Critical CVSS" : "CVSS recorded",
      tone: finding.cvss_base_score >= 9 ? "critical" : "info",
    })
  }

  if (finding && isInternetFacingExposure(finding.exposure)) {
    rows.push({
      detail: `${findingAssetLabel(finding)} is marked ${labelize(finding.exposure)}, increasing remediation urgency.`,
      label: "Internet-facing asset",
      tone: "critical",
    })
  }

  if (isProductionEnvironment(finding?.asset_environment)) {
    rows.push({
      detail: `Environment is marked ${labelize(finding?.asset_environment)}, so operational exposure is higher.`,
      label: "Production service",
      tone: "warning",
    })
  }

  if (!attackContextEmptyState(attackContext)) {
    rows.push({
      detail: `${attackTechniqueRows(attackContext).length} reviewed ATT&CK technique mapping(s) are available for defensive context.`,
      label: "ATT&CK / TTP context",
      tone: "warning",
    })
  }

  const defensiveNote = stringValue(attackContext?.defensive_note)
  if (defensiveNote && /gap|missing|coverage|detect/i.test(defensiveNote)) {
    rows.push({
      detail: defensiveNote,
      label: "Detection coverage gap",
      tone: "warning",
    })
  }

  const recommendedAction = findingRecommendedAction(finding, explanation)
  if (recommendedAction !== "No recommended action has been recorded.") {
    rows.push({
      detail: recommendedAction,
      label: "Fix or mitigation",
      tone: "positive",
    })
  }

  if (rows.length === 0) {
    rows.push({
      detail: findingWhyText(finding, explanation),
      label: "Decision rationale",
      tone: "info",
    })
  }

  return rows
}

export function findingReasonRows(
  explanation: FindingExplanationPublic | null,
) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const reasons = arrayRecords(decisionExplanation.reasons)
  return reasons.map((reason, index) => {
    const code =
      stringValue(reason.code) ??
      stringValue(reason.signal) ??
      stringValue(reason.source)
    const detail =
      decisionReasonDetail(
        code,
        stringValue(reason.message) ??
          stringValue(reason.description) ??
          stringValue(reason.detail) ??
          stringValue(reason.value) ??
          null,
      ) ?? "Matched decision signal"
    return {
      detail,
      label: code ? decisionReasonLabel(code) : `Reason ${index + 1}`,
    }
  })
}

export function findingDataQualityRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const flags =
    explanation?.data_quality_flags ??
    arrayRecords(objectRecord(finding?.data_quality_json).flags)
  return flags.map((flag, index) => ({
    code: stringValue(flag.code) ?? "data_quality_flag",
    key: [flag.source, flag.code, flag.message, index].join(":"),
    message: stringValue(flag.message) ?? "Data quality flag recorded.",
    severity: stringValue(flag.severity) ?? "info",
    source: stringValue(flag.source) ?? "provider",
  }))
}

export function findingProviderGaps(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  if (!finding) {
    return []
  }
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding.explanation_json).provider_evidence,
  )
  const gaps: string[] = []
  if (finding.epss === null || finding.epss === undefined) {
    gaps.push("EPSS missing")
  }
  if (
    finding.cvss_base_score === null ||
    finding.cvss_base_score === undefined
  ) {
    gaps.push("CVSS missing")
  }
  if (Object.keys(providerEvidence).length === 0) {
    gaps.push("Provider evidence missing")
  }
  return gaps
}

export function findingEvidenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
  dataQualityRows: ReturnType<typeof findingDataQualityRows>,
  providerGaps: readonly string[],
): FindingDetailRow[] {
  const firstOccurrence = occurrences[0]
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding?.explanation_json).provider_evidence,
  )
  const evidence = objectRecord(finding?.evidence_json)
  const providerSignalLabels = [
    finding?.epss !== null && finding?.epss !== undefined ? "EPSS" : null,
    finding?.cvss_base_score !== null && finding?.cvss_base_score !== undefined
      ? "CVSS"
      : null,
    finding?.in_kev ? "CISA KEV" : null,
  ].filter((label): label is string => Boolean(label))
  const providerKeys = Object.keys(providerEvidence)
  const artifactRef =
    stringValue(evidence.report_artifact) ??
    stringValue(evidence.report_reference) ??
    stringValue(evidence.artifact_reference) ??
    stringValue(firstOccurrence?.vex_source_path)

  return [
    {
      detail:
        providerGaps.length > 0
          ? `Gaps: ${providerGaps.join(", ")}`
          : "No provider gaps recorded for the stored finding signals.",
      label: "Provider snapshot",
      value:
        providerKeys.length > 0
          ? `${providerKeys.length} provider evidence field(s) recorded`
          : providerSignalLabels.length > 0
            ? providerSignalLabels.join(", ")
            : "No provider snapshot recorded",
    },
    {
      detail: optionalText(
        stringValue(firstOccurrence?.source_record_id) ??
          stringValue(firstOccurrence?.raw_reference) ??
          stringValue(firstOccurrence?.source_id),
      ),
      label: "Input source",
      value: optionalText(
        stringValue(firstOccurrence?.source_format) ??
          stringValue(firstOccurrence?.source) ??
          stringValue(evidence.input_source),
      ),
    },
    {
      detail: optionalText(stringValue(firstOccurrence?.raw_severity)),
      label: "Scanner evidence",
      value: optionalText(
        stringValue(firstOccurrence?.scanner) ??
          stringValue(evidence.scanner) ??
          stringValue(evidence.tool),
      ),
    },
    {
      detail:
        dataQualityRows.length > 0
          ? dataQualityRows.map((row) => labelize(row.code)).join(", ")
          : "No data quality flags recorded.",
      label: "Data quality notes",
      value:
        explanation?.data_quality_confidence ??
        stringValue(objectRecord(finding?.data_quality_json).confidence) ??
        "Recorded",
    },
    {
      detail:
        "Report or evidence bundle reference when supplied by input data.",
      label: "Report / artifact references",
      value: optionalText(artifactRef),
    },
  ]
}

function formatFindingDateTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

export function findingHistoryRows(
  finding: FindingDetailPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
  waiverEvidence: FindingWaiverEvidence | null,
): FindingDetailRow[] {
  const vexStatus =
    occurrences
      .map((occurrence) => stringValue(occurrence.vex_status))
      .find(Boolean) ?? null
  const vexDetail =
    occurrences
      .map((occurrence) =>
        joinedValues([
          stringValue(occurrence.vex_justification),
          stringValue(occurrence.vex_action_statement),
          stringValue(occurrence.vex_match_type),
        ]),
      )
      .find((value) => value !== "N.A.") ?? null

  return [
    {
      detail: "Initial source occurrence recorded by Workbench.",
      label: "First seen",
      value: finding?.first_seen_at
        ? formatFindingDateTime(finding.first_seen_at)
        : "N.A.",
    },
    {
      detail: "Most recent source occurrence recorded by Workbench.",
      label: "Last seen",
      value: finding?.last_seen_at
        ? formatFindingDateTime(finding.last_seen_at)
        : "N.A.",
    },
    {
      detail: finding?.updated_at
        ? `Last updated ${formatFindingDateTime(finding.updated_at)}`
        : "No status update timestamp recorded.",
      label: "Status changes",
      value: labelize(finding?.status),
    },
    {
      detail:
        waiverEvidence?.reason ??
        vexDetail ??
        "No waiver or VEX state recorded for this finding.",
      label: "Waiver / VEX state",
      value: finding?.waived
        ? `Waived${waiverEvidence?.status ? ` (${labelize(waiverEvidence.status)})` : ""}`
        : finding?.suppressed_by_vex
          ? "Suppressed by VEX"
          : vexStatus
            ? labelize(vexStatus)
            : "Not accepted",
    },
  ]
}

export function demoFindingDetailForId(findingId: string) {
  const demoFinding = DEMO_FINDINGS.find((finding) => finding.id === findingId)
  if (!demoFinding) {
    return null
  }
  const createdAt = demoFinding.created_at ?? "2025-04-01T00:00:00Z"
  const lastSeenAt = demoFinding.last_seen_at ?? createdAt
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
    },
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

export function attackTechniqueRows(context: FindingAttackContext | null) {
  if (!context) {
    return []
  }
  const techniques = context.techniques ?? []
  if (techniques.length > 0) {
    return techniques
  }
  return (context.mappings ?? []).map((mapping) => ({
    confidence: mapping.confidence,
    defensive_note: mapping.defensive_note,
    name: mapping.technique_name,
    rationale: mapping.rationale,
    review_status: mapping.review_status,
    source: mapping.source,
    tactics: mapping.tactics ?? [],
    technique_id: mapping.technique_id,
    url: null,
  }))
}

export function attackTacticsLabel(values: string[] | null | undefined) {
  return values && values.length > 0 ? values.join(", ") : "N.A."
}

export function attackConfidenceLabel(value: string | null | undefined) {
  return value ? labelize(value) : "Unknown"
}

export function attackSourceLabel(
  source: string | null | undefined,
  context: FindingAttackContext | null,
) {
  const references = (context?.mappings ?? []).flatMap(
    (mapping) => mapping.references ?? [],
  )
  if (
    references.some((reference) =>
      reference.toLowerCase().includes("local curated demo mapping"),
    )
  ) {
    return "Local curated demo mapping"
  }
  if (source === "local-curated") {
    return "Local curated mapping"
  }
  return source ?? null
}

export function attackCoverageStatusLabel(
  context: FindingAttackContext | null,
) {
  const note = (stringValue(context?.defensive_note) ?? "").toLowerCase()
  if (!note) {
    return "Not recorded"
  }
  if (/partial|unknown/.test(note)) {
    return "Partial / unknown"
  }
  if (/gap|missing|validate|coverage|detect/.test(note)) {
    return "Needs validation"
  }
  return "Recorded"
}

export function defensiveActionItems(value: string | null | undefined) {
  return (value ?? "")
    .split(/\n+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function attackContextEmptyState(context: FindingAttackContext | null) {
  return (
    !context ||
    context.mapped !== true ||
    attackTechniqueRows(context).length === 0
  )
}
