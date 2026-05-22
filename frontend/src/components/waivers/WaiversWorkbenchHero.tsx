import { Link } from "@/lib/router"
import {
  AlertTriangle,
  CalendarClock,
  ClipboardCheck,
  ExternalLink,
  FileCheck2,
  History,
  Plus,
  ShieldCheck,
} from "lucide-react"
import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  VpwCommandPanel,
  VpwCompactMetric,
  VpwField,
  VpwMetricStrip,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
  type VpwMetricTone,
} from "@/components/vpw"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiversHero({
  openWaiverDrawer,
  onProjectChange,
  projectListLoading,
  projectSummary,
  projects,
  selectedProject,
  selectedProjectId,
}: Pick<
  WaiversWorkbenchProps,
  | "openWaiverDrawer"
  | "onProjectChange"
  | "projectListLoading"
  | "projectSummary"
  | "projects"
  | "selectedProject"
  | "selectedProjectId"
> & {}) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const evidenceAvailable = Boolean(projectSummary?.latest_run_id)

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
        <div className="waivers-context-strip">
          <div className="waivers-project-control">
            <VpwField className="w-full min-w-0" label="Project">
              <Select
                disabled={projectListLoading || projects.length === 0}
                onValueChange={onProjectChange}
                value={selectedProjectId}
              >
                <SelectTrigger aria-label="Risk Acceptance project">
                  <SelectValue placeholder="Select project" />
                </SelectTrigger>
                <SelectContent>
                  {projects.length === 0 ? (
                    <SelectItem disabled value="none">
                      No projects
                    </SelectItem>
                  ) : null}
                  {projects.map((project) => (
                    <SelectItem key={project.id} value={project.id}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <small className="waivers-project-control__hint">
                {selectedProject
                  ? `${selectedProject.name} acceptance scope`
                  : "Select a project to review accepted risk"}
              </small>
            </VpwField>
          </div>
          <VpwMetricStrip minCardWidth="14rem">
            <WaiverContextItem
              description="Accepted findings stay auditable"
              icon={<ShieldCheck aria-hidden="true" />}
              label="Triage visibility"
              tone="success"
              value="Always visible"
            />
            <WaiverContextItem
              description={
                evidenceAvailable
                  ? "Latest import evidence can support decisions"
                  : "Record approval references before relying on exceptions"
              }
              icon={<FileCheck2 aria-hidden="true" />}
              label="Evidence"
              tone={evidenceAvailable ? "success" : "warning"}
              value={evidenceAvailable ? "Available" : "Pending"}
            />
            <WaiverContextItem
              description="Owner, scope, review, and expiry are required"
              icon={<History aria-hidden="true" />}
              label="Lifecycle"
              value="Time-boxed"
            />
          </VpwMetricStrip>
        </div>
      </VpwCommandPanel>
    </VpwSection>
  )
}

function WaiverContextItem({
  description,
  icon,
  label,
  tone = "neutral",
  value,
}: {
  description: string
  icon: ReactNode
  label: string
  tone?: VpwMetricTone
  value: string
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

export function WaiverMetrics({
  acceptedFindings,
  activeWaivers,
  expiringSoon,
  missingApprovals,
  reviewDue,
  waiversLoading,
}: Pick<WaiversWorkbenchProps, "waiversLoading"> & {
  acceptedFindings: string
  activeWaivers: number
  expiringSoon: string
  missingApprovals: number
  reviewDue: string
}) {
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
        tone={Number(reviewDue) > 0 ? "warning" : "neutral"}
        value={reviewDue}
      />
      <WaiverKpiCard
        description="within the review window"
        icon={<CalendarClock aria-hidden="true" className="h-4 w-4" />}
        label="Expiring soon"
        tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}
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
  tone?: VpwMetricTone
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
