import type { FindingAttackContextDetailPublic } from "@/api-client"

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
