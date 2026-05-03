import { Link } from "@tanstack/react-router"
import { Eye } from "lucide-react"

import type { FindingPublic } from "../../api-client"
import { optionalText } from "../../lib/ui-copy"
import { PriorityBadge, RiskScore } from "../risk"
import { EmptyState, ErrorState, LoadingSkeleton } from "../states"

type TopRemediationQueueProps = {
  error: string
  findings: readonly FindingPublic[]
  loading: boolean
  projectName: string | null | undefined
}

function findingComponentLabel(finding: FindingPublic) {
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

function findingOwnerLabel(finding: FindingPublic) {
  return finding.owner ?? finding.business_service ?? "Unassigned"
}

function findingServiceLabel(finding: FindingPublic) {
  return finding.business_service ?? "Service not linked"
}

function findingWhyNow(finding: FindingPublic) {
  return (
    optionalText(finding.rationale) ??
    optionalText(finding.recommended_action) ??
    "No priority rationale has been recorded yet."
  )
}

function formatDateTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

export function TopRemediationQueue({
  error,
  findings,
  loading,
  projectName,
}: TopRemediationQueueProps) {
  return (
    <section
      className="top-remediation-panel"
      aria-label="Top Remediation Queue"
    >
      <div className="dashboard-panel-heading">
        <div>
          <span>Remediation Focus</span>
          <h3>Top Remediation Queue</h3>
          <p>
            Highest operational findings for{" "}
            {projectName ? projectName : "the selected project"}.
          </p>
        </div>
        <Link className="secondary-action compact-action" to="/findings">
          Findings
        </Link>
      </div>

      {error ? <ErrorState message={error} /> : null}

      {loading ? (
        <LoadingSkeleton label="Loading top remediation queue" />
      ) : null}

      {!loading && !error && findings.length === 0 ? (
        <EmptyState
          action={
            <div className="empty-actions">
              <Link className="primary-action" to="/imports">
                Imports
              </Link>
              <Link className="secondary-action" to="/projects">
                Projects
              </Link>
            </div>
          }
          ariaLabel="No remediation queue"
          compact
          detail="Import scanner, SBOM, or CVE-list data to create prioritized findings."
          title="No findings ready for remediation"
        />
      ) : null}

      {!loading && !error && findings.length > 0 ? (
        <div className="remediation-table-wrap">
          <table className="remediation-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Score</th>
                <th>CVE</th>
                <th>Component / Service</th>
                <th>Owner</th>
                <th>Why now</th>
                <th>View</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <PriorityBadge priority={finding.priority} />
                  </td>
                  <td>
                    <RiskScore value={finding.risk_score} />
                  </td>
                  <td>
                    <Link
                      className="finding-cve-link"
                      title={`Open finding ${finding.cve_id}`}
                      params={{ findingId: finding.id }}
                      to="/findings/$findingId"
                    >
                      {finding.cve_id}
                    </Link>
                  </td>
                  <td>
                    <strong>{findingComponentLabel(finding)}</strong>
                    <span className="remediation-subtext">
                      {findingServiceLabel(finding)}
                    </span>
                  </td>
                  <td>
                    <strong>{findingOwnerLabel(finding)}</strong>
                  </td>
                  <td>
                    <span className="remediation-why-now">
                      {findingWhyNow(finding)}
                    </span>
                  </td>
                  <td>
                    <Link
                      className="finding-view-action"
                      title={`Open finding ${finding.cve_id}`}
                      params={{ findingId: finding.id }}
                      to="/findings/$findingId"
                    >
                      <Eye aria-hidden="true" size={16} />
                      <span className="sr-only">Open finding</span>
                    </Link>
                    <span className="remediation-subtext">
                      {formatDateTime(finding.last_seen_at)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}
