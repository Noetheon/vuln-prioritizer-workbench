import { Link } from "@/lib/router"
import { ExternalLink, Eye } from "lucide-react"

import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  MetaTag,
  RiskBadge,
  RiskScoreBadge,
  SignalChip,
  StatusLozenge,
  VpwSignalCluster,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
import {
  assetLabel,
  componentLabel,
  findingActionLabel,
  findingSlaLabel,
  findingWhyNowCompact,
  formatShortDate,
  ownerLabel,
  serviceLabel,
} from "./FindingsDataTableModel"
import type { FindingsUrlSearch } from "./findings-search-state"

type FindingsMobileCardsProps = {
  findings: readonly FindingPublic[]
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
}

export function FindingsMobileCards({
  findings,
  findingSearch,
  onOpenSheet,
}: FindingsMobileCardsProps) {
  return (
    <section
      aria-label="Findings remediation cards"
      className="findings-mobile-cards"
      data-testid="findings-mobile-cards"
    >
      {findings.map((finding) => {
        const actionLabel = findingActionLabel(finding)
        return (
          <article
            aria-label={`Finding ${actionLabel}`}
            className="findings-mobile-card"
            data-testid="findings-mobile-card"
            key={finding.id}
          >
            <div className="findings-mobile-card-header">
              <div className="findings-mobile-card-title">
                <RiskBadge density="compact" level={finding.priority} />
                <Link
                  className="finding-cve-link findings-mobile-cve"
                  params={{ findingId: finding.id }}
                  search={findingSearch}
                  title={`Open finding ${actionLabel}`}
                  to="/findings/$findingId"
                >
                  {finding.cve_id}
                </Link>
              </div>
              <RiskScoreBadge density="compact" value={finding.risk_score} />
            </div>

            <div className="findings-mobile-component">
              <strong
                className="findings-mobile-component-name"
                title={componentLabel(finding)}
              >
                {componentLabel(finding)}
              </strong>
              <span
                className="findings-mobile-component-detail"
                title={`${serviceLabel(finding)} / ${assetLabel(finding)}`}
              >
                {serviceLabel(finding)} / {assetLabel(finding)}
              </span>
              <div className="finding-meta-tags">
                {finding.asset_environment ? (
                  <MetaTag label={labelize(finding.asset_environment)} />
                ) : null}
                {finding.exposure ? (
                  <MetaTag label={labelize(finding.exposure)} />
                ) : null}
              </div>
            </div>

            <div className="findings-mobile-meta-grid">
              <div>
                <span className="findings-mobile-label">Owner</span>
                <strong className="findings-mobile-meta-value">
                  {ownerLabel(finding)}
                </strong>
                {finding.exposure ? (
                  <small className="findings-mobile-meta-detail">
                    {labelize(finding.exposure)}
                  </small>
                ) : null}
              </div>
              <div>
                <span className="findings-mobile-label">Status</span>
                <StatusLozenge density="compact" status={finding.status} />
                <small className="findings-mobile-meta-detail">
                  {formatShortDate(finding.last_seen_at)}
                </small>
                <div className="finding-meta-tags">
                  <MetaTag label={findingSlaLabel(finding.priority)} />
                </div>
              </div>
            </div>

            <div className="findings-mobile-signals">
              <VpwSignalCluster maxVisible={3}>
                {finding.in_kev ? <SignalChip kind="kev" /> : null}
                {finding.epss !== null && finding.epss !== undefined ? (
                  <SignalChip kind="epss" value={finding.epss} />
                ) : null}
                {finding.cvss_base_score !== null &&
                finding.cvss_base_score !== undefined ? (
                  <SignalChip kind="cvss" value={finding.cvss_base_score} />
                ) : null}
                {finding.attack_mapped ? <SignalChip kind="attack" /> : null}
                {finding.suppressed_by_vex ? <SignalChip kind="vex" /> : null}
              </VpwSignalCluster>
            </div>

            <p className="findings-mobile-why">
              {findingWhyNowCompact(finding)}
            </p>

            <div className="findings-mobile-card-actions">
              <Button asChild className="h-8 px-2" size="sm" variant="outline">
                <Link
                  aria-label={`Open full detail ${actionLabel}`}
                  params={{ findingId: finding.id }}
                  search={findingSearch}
                  to="/findings/$findingId"
                >
                  <ExternalLink aria-hidden="true" size={14} />
                  Full detail
                </Link>
              </Button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    aria-label={`Quick view ${actionLabel}`}
                    className="finding-view-action"
                    onClick={() => onOpenSheet(finding)}
                    type="button"
                    variant="ghost"
                  >
                    <Eye aria-hidden="true" size={16} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="left">Quick view</TooltipContent>
              </Tooltip>
            </div>
          </article>
        )
      })}
    </section>
  )
}
