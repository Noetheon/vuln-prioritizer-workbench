export function sbomAssessmentOutcome(assessment: {
  status?: "complete" | "partial"
  scanner_match_count: number
  prioritized_match_count: number
}) {
  if (assessment.status !== "complete") {
    return {
      title: "SBOM assessment is partial",
      tone: "warning" as const,
      description:
        "Some evidence could not be assessed or recorded completely. Review the limitations before using these results.",
    }
  }
  if (assessment.scanner_match_count === 0) {
    return {
      title: "SBOM scan completed with no matches",
      tone: "success" as const,
      description:
        "Grype found no known vulnerability matches in this inventory using the recorded database. This does not prove the software is free of vulnerabilities.",
    }
  }
  return {
    title: "SBOM scan completed",
    tone: "info" as const,
    description:
      assessment.prioritized_match_count > 0
        ? "Scanner matches with usable CVE identifiers were passed to prioritization."
        : "Scanner matches were recorded, but none could be passed to CVE prioritization. Review the scan evidence.",
  }
}
