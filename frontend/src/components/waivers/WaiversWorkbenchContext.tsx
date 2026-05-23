import { Link } from "@/lib/router"
import {
  AlertTriangle,
  CalendarClock,
  ClipboardCheck,
  ExternalLink,
  FileCheck2,
  Plus,
  ShieldCheck,
} from "lucide-react"
import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwCommandPanel,
  VpwCompactMetric,
  VpwMetricStrip,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
  type VpwCompactTone,
} from "@/components/vpw"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

type WaiverMetricValues = Pick<WaiversWorkbenchProps, "waiversLoading"> & {
  acceptedFindings: string
  activeWaivers: number
  expiringSoon: string
  missingApprovals: number
  reviewDue: string
}

export function WaiversContext({
  acceptedFindings,
  activeWaivers,
  expiringSoon,
  missingApprovals,
  openWaiverDrawer,
  projectListLoading,
  projects,
  reviewDue,
  selectedProjectId,
  waiversLoading,
}: Pick<
  WaiversWorkbenchProps,
  | "openWaiverDrawer"
  | "projectListLoading"
  | "projects"
  | "selectedProjectId"
> &
  WaiverMetricValues) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <VpwSection className="waivers-command-section">
      <VpwCommandPanel
        actions={
          <VpwToolbar
            className="waivers-command-actions"
            label="Risk Acceptance actions"
            variant="plain"
          >
            <VpwToolbarGroup className="waivers-command-actions__group">
              <Button
                disabled={projectListLoading || projects.length === 0}
                onClick={() => openWaiverDrawer("create")}
                type="button"
              >
                <Plus aria-hidden="true" data-icon="inline-start" />
                Record accepted risk
              </Button>
              <Button asChild variant="outline">
                <Link
                  search={{ ...projectSearch, status: "accepted" }}
                  to="/findings"
                >
                  <ExternalLink aria-hidden="true" data-icon="inline-start" />
                  Open accepted findings
                </Link>
              </Button>
            </VpwToolbarGroup>
          </VpwToolbar>
        }
        description="Govern time-boxed exceptions with owner, scope, expiry, and supporting evidence. Accepted risk remains visible in Triage and Finding Detail."
        eyebrow="Risk acceptance"
        title="Accepted risk control center"
      >
        <WaiverMetrics
          acceptedFindings={acceptedFindings}
          activeWaivers={activeWaivers}
          expiringSoon={expiringSoon}
          missingApprovals={missingApprovals}
          reviewDue={reviewDue}
          waiversLoading={waiversLoading}
        />
      </VpwCommandPanel>
    </VpwSection>
  )
}

export function WaiverMetrics({
  acceptedFindings,
  activeWaivers,
  expiringSoon,
  missingApprovals,
  reviewDue,
  waiversLoading,
}: WaiverMetricValues) {
  return (
    <VpwMetricStrip
      aria-label="Risk acceptance summary"
      className="waivers-kpi-strip"
      minCardWidth="11.5rem"
    >
      <WaiverKpiCard
        description="accepted risk currently active"
        icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
        label="Active decisions"
        tone="success"
        value={waiversLoading ? "Loading" : activeWaivers}
      />
      <WaiverKpiCard
        description="requires owner review"
        icon={<ClipboardCheck aria-hidden="true" className="h-4 w-4" />}
        label="Review due"
        tone={Number(reviewDue) > 0 ? "warning" : "success"}
        value={reviewDue}
      />
      <WaiverKpiCard
        description="within the review window"
        icon={<CalendarClock aria-hidden="true" className="h-4 w-4" />}
        label="Expiring soon"
        tone={Number(expiringSoon) > 0 ? "warning" : "success"}
        value={expiringSoon}
      />
      <WaiverKpiCard
        description="findings currently accepted"
        icon={<FileCheck2 aria-hidden="true" className="h-4 w-4" />}
        label="Accepted findings"
        tone="info"
        value={acceptedFindings}
      />
      <WaiverKpiCard
        description="missing approval reference or ticket"
        icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
        label="Evidence incomplete"
        tone={missingApprovals > 0 ? "warning" : "success"}
        value={waiversLoading ? "Loading" : missingApprovals}
      />
    </VpwMetricStrip>
  )
}

function WaiverKpiCard({
  description,
  icon,
  label,
  tone = "neutral",
  value,
}: {
  description: string
  icon: ReactNode
  label: string
  tone?: VpwCompactTone
  value: ReactNode
}) {
  return (
    <VpwCompactMetric
      description={description}
      icon={icon}
      label={label}
      tone={tone}
      value={value}
    />
  )
}
