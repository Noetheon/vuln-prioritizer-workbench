import { Link } from "@/lib/router"
import {
  AlertTriangle,
  CalendarClock,
  ClipboardCheck,
  FileCheck2,
  ShieldCheck,
} from "lucide-react"
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
  VpwBadge,
  VpwField,
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiversHero({
  activeWaivers,
  expired,
  expiringSoon,
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
> & {
  activeWaivers: number
  expired: string
  expiringSoon: string
}) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          actions={
            <>
              <Button
                disabled={projectListLoading || projects.length === 0}
                onClick={() => openWaiverDrawer("create")}
                type="button"
              >
                Create acceptance
              </Button>
              <Button asChild variant="outline">
                <Link search={projectSearch} to="/findings">
                  View findings
                </Link>
              </Button>
            </>
          }
          description="Govern accepted risk decisions with owner, scope, expiry and evidence."
          eyebrow="Risk acceptance"
          title="Risk Acceptance"
        />
        <VpwToolbar label="Waiver context" variant="plain">
          <VpwToolbarGroup className="min-w-0">
            <VpwField className="w-full min-w-0 sm:w-64" label="Project">
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
            </VpwField>
          </VpwToolbarGroup>
          <VpwToolbarGroup>
            <VpwBadge tone={selectedProject ? "success" : "warning"}>
              Active project: {selectedProject?.name ?? "None"}
            </VpwBadge>
            <VpwBadge tone="info">Active: {activeWaivers}</VpwBadge>
            <VpwBadge tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}>
              Expiring soon: {expiringSoon}
            </VpwBadge>
            <VpwBadge tone={Number(expired) > 0 ? "critical" : "neutral"}>
              Expired: {expired}
            </VpwBadge>
            <VpwBadge
              tone={projectSummary?.latest_run_id ? "success" : "neutral"}
            >
              Evidence {projectSummary?.latest_run_id ? "ready" : "pending"}
            </VpwBadge>
          </VpwToolbarGroup>
        </VpwToolbar>
      </VpwPanel>
    </VpwSection>
  )
}

export function WaiverMetrics({
  acceptedFindings,
  activeWaivers,
  expired,
  expiringSoon,
  missingApprovals,
  waiversLoading,
}: Pick<WaiversWorkbenchProps, "waiversLoading"> & {
  acceptedFindings: string
  activeWaivers: number
  expired: string
  expiringSoon: string
  missingApprovals: number
}) {
  return (
    <VpwGrid columns={1} className="md:grid-cols-2 xl:grid-cols-5">
      <VpwMetricCard
        description="currently accepted risk"
        icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
        label="Active acceptances"
        tone="success"
        value={waiversLoading ? "Loading" : activeWaivers}
      />
      <VpwMetricCard
        description="within the review window"
        icon={<CalendarClock aria-hidden="true" className="h-4 w-4" />}
        label="Expiring soon"
        tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}
        value={expiringSoon}
      />
      <VpwMetricCard
        description="past expiry date"
        icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
        label="Expired acceptances"
        tone={Number(expired) > 0 ? "critical" : "neutral"}
        value={expired}
      />
      <VpwMetricCard
        description="findings currently accepted"
        icon={<FileCheck2 aria-hidden="true" className="h-4 w-4" />}
        label="Accepted findings"
        tone="info"
        value={acceptedFindings}
      />
      <VpwMetricCard
        description="missing approval reference or ticket"
        icon={<ClipboardCheck aria-hidden="true" className="h-4 w-4" />}
        label="Incomplete evidence"
        tone={missingApprovals > 0 ? "warning" : "success"}
        value={waiversLoading ? "Loading" : missingApprovals}
      />
    </VpwGrid>
  )
}
