import { Link } from "@/lib/router"
import type { FindingPublic } from "@/api-client"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { VpwStatusBanner } from "@/components/vpw"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingsUrlSearch } from "./findings-search-state"
import { componentLabel } from "./remediation-queue-model"

type WhyDialogProps = {
  finding: FindingPublic | null
  open: boolean
  onClose: () => void
}

export function WhyDialog({ finding, open, onClose }: WhyDialogProps) {
  if (!finding) return null
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-lg text-[var(--vpw-text-primary)]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PriorityBadge priority={finding.priority} />
            <span className="font-mono text-sm">{finding.cve_id}</span>
          </DialogTitle>
          <DialogDescription className="sr-only">
            Priority rationale, risk signals, and recommended remediation action
            for {finding.cve_id}.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4 text-sm">
          {finding.rationale ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase text-[var(--vpw-text-secondary)]">
                Why now
              </p>
              <p className="leading-relaxed">{finding.rationale}</p>
            </div>
          ) : (
            <p className="text-[var(--vpw-text-secondary)]">
              No rationale recorded for this finding.
            </p>
          )}
          {finding.recommended_action ? (
            <VpwStatusBanner title="Recommended action" tone="success">
              {finding.recommended_action}
            </VpwStatusBanner>
          ) : null}
          <dl className="grid grid-cols-3 gap-3 rounded-md border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3 text-xs text-[var(--vpw-text-primary)]">
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">Risk Score</dt>
              <dd className="font-bold text-sm text-[var(--vpw-text-primary)]">
                {finding.risk_score?.toFixed(1) ?? "N.A."}
              </dd>
            </div>
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">EPSS</dt>
              <dd className="font-semibold text-sm">
                <EpssBadge value={finding.epss} />
              </dd>
            </div>
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">KEV</dt>
              <dd className="font-semibold text-sm">
                <KevBadge matched={finding.in_kev} />
              </dd>
            </div>
          </dl>
        </div>
      </DialogContent>
    </Dialog>
  )
}

type QuickViewSheetProps = {
  finding: FindingPublic | null
  findingSearch: FindingsUrlSearch
  open: boolean
  onClose: () => void
}

export function QuickViewSheet({
  finding,
  findingSearch,
  open,
  onClose,
}: QuickViewSheetProps) {
  if (!finding) return null
  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-96 overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="font-mono text-base">
            {finding.cve_id}
          </SheetTitle>
          <SheetDescription className="sr-only">
            Condensed remediation details and full finding detail link for{" "}
            {finding.cve_id}.
          </SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-5 mt-6 text-sm">
          <div className="flex flex-wrap gap-2">
            <PriorityBadge priority={finding.priority} />
            <FindingStatusBadge status={finding.status} />
            <KevBadge matched={finding.in_kev} />
          </div>

          <dl className="grid grid-cols-2 gap-3">
            {[
              {
                label: "Risk Score",
                value: finding.risk_score?.toFixed(1) ?? "N.A.",
              },
              { label: "EPSS", value: <EpssBadge value={finding.epss} /> },
              {
                label: "CVSS",
                value: <CvssBadge value={finding.cvss_base_score} />,
              },
              { label: "Exposure", value: labelize(finding.exposure) },
              { label: "Owner", value: optionalText(finding.owner) },
              {
                label: "Service",
                value: optionalText(finding.business_service),
              },
            ].map(({ label, value }) => (
              <div key={label}>
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="font-medium mt-0.5">{value}</dd>
              </div>
            ))}
          </dl>

          <div>
            <p className="text-xs font-semibold uppercase text-muted-foreground mb-1">
              Component
            </p>
            <p className="font-medium">{componentLabel(finding)}</p>
            {finding.component_purl ? (
              <p className="text-xs text-muted-foreground mt-0.5 break-all">
                {finding.component_purl}
              </p>
            ) : null}
          </div>

          {finding.rationale ? (
            <div>
              <p className="text-xs font-semibold uppercase text-muted-foreground mb-1">
                Rationale
              </p>
              <p className="leading-relaxed text-sm">{finding.rationale}</p>
            </div>
          ) : null}

          {finding.recommended_action ? (
            <VpwStatusBanner title="Recommended action" tone="success">
              {finding.recommended_action}
            </VpwStatusBanner>
          ) : null}

          <div className="pt-2 border-t">
            <Button asChild className="w-full" size="sm" variant="outline">
              <Link
                params={{ findingId: finding.id }}
                search={findingSearch}
                to="/findings/$findingId"
              >
                Open full detail
              </Link>
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}
