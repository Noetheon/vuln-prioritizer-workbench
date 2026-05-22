import {
  SourceMark,
  VpwDataTable,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"

import { compactFindingText } from "./finding-detail-model"

type FindingRationaleLedgerProps = {
  contextSummary: readonly string[]
  reasonRows: readonly { detail: string; label: string }[]
  signalSummary: readonly string[]
}

type RationaleLedgerRow = {
  impact: string
  label: string
  providerStatement: string
  source: string
}

function rationaleSource(label: string, detail: string) {
  const value = `${label} ${detail}`
  if (/kev|cisa/i.test(value)) return "KEV"
  if (/epss/i.test(value)) return "EPSS"
  if (/cvss|severity/i.test(value)) return "NVD"
  if (/asset|owner|service|environment|exposure|production/i.test(value)) {
    return "Asset context"
  }
  if (/vex|waiver|governance|accept/i.test(value)) return "Governance"
  return "Provider snapshot"
}

function rationaleImpact(label: string, detail: string) {
  const value = `${label} ${detail}`
  if (/kev|critical|escalat|high|threshold|increase/i.test(value)) {
    return "Raises priority"
  }
  if (/vex|suppress|accept|waiver|fixed/i.test(value)) {
    return "Adjusts governance state"
  }
  if (/missing|unknown|gap/i.test(value)) {
    return "Needs validation"
  }
  return "Explains score"
}

export function FindingRationaleLedger({
  contextSummary,
  reasonRows,
  signalSummary,
}: FindingRationaleLedgerProps) {
  if (reasonRows.length === 0) {
    return null
  }
  const rows = reasonRows.map((reason) => ({
    impact: rationaleImpact(reason.label, reason.detail),
    label: labelize(reason.label),
    providerStatement: reason.detail,
    source: rationaleSource(reason.label, reason.detail),
  }))
  const columns: readonly VpwDataTableColumn<RationaleLedgerRow>[] = [
    {
      cell: (row) => <strong>{row.label}</strong>,
      header: "Reason",
      id: "reason",
      width: "16rem",
    },
    {
      cell: (row) => (
        <span title={row.providerStatement}>
          {compactFindingText(
            row.providerStatement,
            row.providerStatement.length > 160 ? 300 : 220,
          )}
        </span>
      ),
      header: "Provider statement",
      id: "statement",
    },
    {
      cell: (row) => <SourceMark source={row.source} />,
      header: "Source",
      id: "source",
      width: "12rem",
    },
    {
      cell: (row) => row.impact,
      header: "Impact on priority",
      id: "impact",
      width: "12rem",
    },
  ]

  return (
    <details className="finding-provider-reasons">
      <summary>
        <div>
          <span>Stored rationale ledger</span>
          <strong>Provider decision audit trail</strong>
          <p>
            Audit trail from the provider decision payload. This explains why
            the finding was ranked. It is not additional remediation work.
          </p>
        </div>
        <div className="finding-provider-reasons__summary-action">
          <span className="finding-provider-reasons__count">
            {reasonRows.length} reason{reasonRows.length === 1 ? "" : "s"}
          </span>
        </div>
      </summary>
      <div className="finding-provider-reasons__body">
        <dl className="finding-provider-reasons__stats">
          <div>
            <dt>Signal evidence</dt>
            <dd>
              {signalSummary.length > 0
                ? signalSummary.join(", ")
                : "No provider signal"}
            </dd>
          </div>
          <div>
            <dt>Context applied</dt>
            <dd>
              {contextSummary.length > 0
                ? contextSummary.join(", ")
                : "No context applied"}
            </dd>
          </div>
          <div>
            <dt>Raw audit trail</dt>
            <dd>
              {reasonRows.length} rationale rule
              {reasonRows.length === 1 ? "" : "s"}
            </dd>
          </div>
        </dl>

        <VpwDataTable
          caption="Provider rationale statements"
          className="finding-provider-reasons__ledger-shell"
          columns={columns}
          data={rows}
          density="compact"
          getRowKey={(row, index) => `${row.label}:${index}`}
          minWidth="860px"
          tableClassName="finding-provider-reasons__ledger"
          variant="detail"
        />
      </div>
    </details>
  )
}
