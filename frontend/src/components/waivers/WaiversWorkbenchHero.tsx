import { Link } from "@/lib/router"
import {
  AlertTriangle,
  CalendarClock,
  ClipboardCheck,
  ExternalLink,
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
  VpwField,
  VpwGrid,
  MetaTag,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwToolbar,
  VpwToolbarGroup,
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
> & {
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
            </>
          }
          description="Govern time-boxed accepted-risk decisions with owner, scope, expiry, and evidence. Accepted risk remains visible in Triage and Finding Detail."
          eyebrow="Risk acceptance"
          title="Accepted risk register"
        />
        <VpwToolbar label="Risk Acceptance context" variant="plain">
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
            <MetaTag label={`Project: ${selectedProject?.name ?? "None"}`} />
            <MetaTag label={`Evidence ${projectSummary?.latest_run_id ? "available" : "pending"}`} />
          </VpwToolbarGroup>
        </VpwToolbar>
      </VpwPanel>
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
}: Pick<WaiversWorkbenchProps, "waiversLoading"> & {
  acceptedFindings: string
  activeWaivers: number
  expiringSoon: string
  missingApprovals: number
  reviewDue: string
}) {
  return (
    <VpwGrid columns={1} className="md:grid-cols-2 xl:grid-cols-5">
      <VpwMetricCard
        description="accepted risk currently active"
        icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
        label="Active decisions"
        tone="success"
        value={waiversLoading ? "Loading" : activeWaivers}
      />
      <VpwMetricCard
        description="requires owner review"
        icon={<ClipboardCheck aria-hidden="true" className="h-4 w-4" />}
        label="Review due"
        tone={Number(reviewDue) > 0 ? "warning" : "neutral"}
        value={reviewDue}
      />
      <VpwMetricCard
        description="within the review window"
        icon={<CalendarClock aria-hidden="true" className="h-4 w-4" />}
        label="Expiring soon"
        tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}
        value={expiringSoon}
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
        icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
        label="Evidence incomplete"
        tone={missingApprovals > 0 ? "warning" : "success"}
        value={waiversLoading ? "Loading" : missingApprovals}
      />
    </VpwGrid>
  )
}
