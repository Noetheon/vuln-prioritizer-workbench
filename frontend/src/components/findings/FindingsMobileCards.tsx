import { Link } from "@tanstack/react-router"
import { Eye } from "lucide-react"

import type { FindingPublic } from "@/api-client"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
  RiskScore,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { VpwBadge } from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
import {
  assetLabel,
  componentLabel,
  findingWhyNow,
  formatShortDate,
  ownerLabel,
  serviceLabel,
} from "./FindingsDataTableModel"
import type { FindingsUrlSearch } from "./findings-search-state"

type FindingsMobileCardsProps = {
  findings: readonly FindingPublic[]
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
}

export function FindingsMobileCards({
  findings,
  findingSearch,
  onOpenSheet,
  onOpenWhy,
}: FindingsMobileCardsProps) {
  return (
    <section
      aria-label="Findings remediation cards"
      className="findings-mobile-cards sm:hidden"
      data-testid="findings-mobile-cards"
    >
      {findings.map((finding) => (
        <article
          aria-label={`Finding ${finding.cve_id}`}
          className="findings-mobile-card"
          data-testid="findings-mobile-card"
          key={finding.id}
        >
          <div className="findings-mobile-card-header">
            <div className="findings-mobile-card-title">
              <PriorityBadge priority={finding.priority} />
              <Link
                className="finding-cve-link findings-mobile-cve"
                params={{ findingId: finding.id }}
                search={findingSearch}
                title={`Open finding ${finding.cve_id}`}
                to="/findings/$findingId"
              >
                {finding.cve_id}
              </Link>
            </div>
            <RiskScore value={finding.risk_score} />
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
              <FindingStatusBadge status={finding.status} />
              <small className="findings-mobile-meta-detail">
                {formatShortDate(finding.last_seen_at)}
              </small>
            </div>
          </div>

          <div className="findings-mobile-signals">
            <VpwBadge className="min-h-6 gap-1.5 px-2 text-[0.72rem]" tone="info">
              <span>EPSS</span>
              <strong className="font-black text-[var(--vpw-text-primary)]">
                <EpssBadge value={finding.epss} />
              </strong>
            </VpwBadge>
            <VpwBadge className="min-h-6 gap-1.5 px-2 text-[0.72rem]" tone="info">
              <span>CVSS</span>
              <strong className="font-black text-[var(--vpw-text-primary)]">
                <CvssBadge value={finding.cvss_base_score} />
              </strong>
            </VpwBadge>
            <KevBadge matched={finding.in_kev} />
          </div>

          <p className="findings-mobile-why">{findingWhyNow(finding)}</p>

          <div className="findings-mobile-card-actions">
            <Button
              className="h-8 justify-start px-0 text-[0.78rem] font-extrabold text-[var(--vpw-text-primary)]"
              onClick={() => onOpenWhy(finding)}
              size="sm"
              type="button"
              variant="link"
            >
              Why now
            </Button>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  aria-label={`Quick view ${finding.cve_id}`}
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
      ))}
    </section>
  )
}
