import type { FindingAttackContextDetailPublic } from "@/api-client"

type MappingSeed = readonly [
  string,
  string,
  string,
  string,
  readonly string[],
  "high" | "medium",
  string,
]

const mappings: readonly MappingSeed[] = [
  ["CVE-2022-22965", "T1190", "Public-facing application exposure review", "defensive_review", ["Initial Access"], "high", "Spring framework exposure review"],
  ["CVE-2021-44228", "T1190", "Public-facing application exposure review", "defensive_review", ["Initial Access"], "high", "Java logging runtime exposure review"],
  ["CVE-2024-4577", "T1190", "Public-facing application exposure review", "defensive_review", ["Initial Access"], "high", "PHP CGI web exposure review"],
  ["CVE-2023-34362", "T1190", "Public-facing application exposure review", "defensive_review", ["Initial Access"], "high", "Managed file-transfer exposure review"],
  ["CVE-2020-1472", "T1210", "Remote services exposure review", "defensive_review", ["Lateral Movement"], "high", "Identity remote service review"],
  ["CVE-2023-44487", "T1499", "Endpoint Denial of Service", "detection_context", ["Impact"], "medium", "Edge availability telemetry review"],
]

const mappingByCve = new Map(mappings.map((mapping) => [mapping[0], mapping]))

const findingCves = {
  "demo-f1": "CVE-2022-22965",
  "demo-f2": "CVE-2021-44228",
  "demo-f4": "CVE-2024-4577",
  "demo-f7": "CVE-2020-1472",
  "demo-f10": "CVE-2023-34362",
  "demo-f16": "CVE-2023-44487",
} as const

function attackContext(cveId: string): FindingAttackContextDetailPublic {
  const mapping = mappingByCve.get(cveId)
  if (!mapping) {
    return {
      attack_relevance: "unmapped",
      confidence: "unknown",
      defensive_note:
        "No reviewed ATT&CK mapping is attached. The CVE remains unmapped; no inference is generated.",
      low_confidence: true,
      mapped: false,
      mappings: [],
      rationale: "Unmapped CVEs remain unmapped in the demo preview.",
      review_status: "unmapped",
      source: "No reviewed mapping",
      tactics: [],
      technique_ids: [],
      techniques: [],
    } as FindingAttackContextDetailPublic
  }
  const [, techniqueId, techniqueName, mappingType, tactics, confidence, title] = mapping
  const defensiveNote =
    "Reviewed defensive context only. Use it for SOC validation and telemetry review; it does not prove compromise or override CVSS, EPSS, KEV, and asset context."
  const technique = {
    confidence,
    defensive_note: defensiveNote,
    name: techniqueName,
    rationale: `${title}. This mapping is defensive review context and contains no procedure instructions.`,
    review_status: "reviewed",
    source: "Local curated demo mapping",
    tactics: [...tactics],
    technique_id: techniqueId,
    url: `https://attack.mitre.org/techniques/${techniqueId}/`,
  }
  return {
    attack_relevance: "defensive_prioritization",
    confidence,
    defensive_note: defensiveNote,
    low_confidence: false,
    mapped: true,
    mappings: [
      {
        ...technique,
        mapping_type: mappingType,
        references: ["Local curated demo mapping"],
        technique_name: techniqueName,
      },
    ],
    rationale: technique.rationale,
    review_status: "reviewed",
    source: "Local curated demo mapping",
    tactics: [...tactics],
    technique_ids: [techniqueId],
    techniques: [technique],
  } as FindingAttackContextDetailPublic
}

export const DEMO_FINDING_ATTACK_CONTEXTS = Object.fromEntries(
  Object.entries(findingCves).map(([findingId, cveId]) => [
    findingId,
    attackContext(cveId),
  ]),
) as Record<string, FindingAttackContextDetailPublic>
