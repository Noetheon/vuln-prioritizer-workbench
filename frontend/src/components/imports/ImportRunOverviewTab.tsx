import { Link } from "@/lib/router"
import {
  CheckCircle2,
  ChevronRight,
  FolderOpen,
  ListChecks,
  UploadCloud,
} from "lucide-react"
import {
  VpwEmptyState,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  importRunTimelineItems,
  objectRecord,
  runFileLabel,
} from "./imports-workbench-model"
import { CopyableValue } from "./ImportDiagnosticsDrawerParts"
import {
  booleanFromRecord,
  RunDetailRows,
  stringFromRecord,
  timelineDetail,
  timelineTime,
  uploadFilename,
  type ImportRun,
  type ImportRunSummary,
} from "./ImportRunDetailTabShared"

export function OverviewTab({
  projectName,
  run,
  summary,
}: {
  projectName?: string
  run: ImportRun
  summary: ImportRunSummary
}) {
  const inputUpload = objectRecord(summary.input_upload)
  const assetContextUpload = objectRecord(summary.asset_context_upload)
  const vexUpload = objectRecord(summary.vex_upload)
  const lockedProviderData =
    booleanLabel(summary.locked_provider_data) ??
    booleanFromRecord(inputUpload, "locked_provider_data") ??
    "Not recorded"
  const timelineItems = importRunTimelineItems(run, summary)
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <VpwPanel>
        <VpwSectionHeader title="Source details" />
        <RunDetailRows
          items={[
            { label: "Project", value: projectName ?? summary.project_id },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            { label: "Original file", value: runFileLabel(summary) },
            {
              label: "Provider snapshot",
              value: summary.provider_snapshot_id ? (
                <CopyableValue
                  label="Copy provider snapshot ID"
                  value={summary.provider_snapshot_id}
                />
              ) : (
                "Not recorded"
              ),
            },
            { label: "Started", value: formatDateTime(summary.started_at) },
            { label: "Finished", value: formatDateTime(summary.finished_at) },
            { label: "Run ID", value: <CopyableValue label="Copy run ID" value={summary.id} /> },
          ]}
        />
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Context overlays" />
        <RunDetailRows
          items={[
            {
              label: "Asset context",
              value:
                uploadFilename(assetContextUpload) ??
                stringFromRecord(inputUpload, "asset_context_filename") ??
                "None",
            },
            {
              label: "VEX",
              value:
                uploadFilename(vexUpload) ??
                stringFromRecord(inputUpload, "vex_filename") ??
                "None",
            },
            {
              label: "ATT&CK context",
              value:
                summary.attack_source ??
                stringFromRecord(inputUpload, "attack_source") ??
                "None",
            },
            {
              label: "Provider data",
              value:
                summary.provider_snapshot_file ??
                stringFromRecord(inputUpload, "provider_snapshot_file") ??
                "Current provider data",
            },
            {
              label: "Deterministic replay",
              value: lockedProviderData,
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="What happened" />
        {timelineItems.length > 0 ? (
          <ol className="grid gap-3 text-sm">
            {timelineItems.map((item) => (
              <li className="grid grid-cols-[1.5rem_minmax(0,1fr)_auto] items-start gap-3" key={item}>
                <CheckCircle2
                  aria-hidden="true"
                  className="mt-0.5 size-4 text-[var(--vpw-green)]"
                />
                <span className="min-w-0">
                  <span className="block font-semibold text-[var(--vpw-text-primary)]">
                    {item}
                  </span>
                  <span className="block text-sm text-[var(--vpw-text-secondary)]">
                    {timelineDetail(item, summary)}
                  </span>
                </span>
                <span className="text-sm text-[var(--vpw-text-secondary)]">
                  {timelineTime(item, summary)}
                </span>
              </li>
            ))}
          </ol>
        ) : (
          <VpwEmptyState title="No timeline metadata recorded" />
        )}
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Next actions" />
        <div className="grid gap-3">
          {[
            {
              description: "Open Triage with this project context preserved.",
              href: "/findings" as const,
              icon: ListChecks,
              label: "Review findings",
              search: { projectId: summary.project_id },
            },
            {
              description: "Review imported file metadata and report artifacts.",
              href: "/reports" as const,
              icon: FolderOpen,
              label: "Inspect evidence",
              search: { projectId: summary.project_id, runId: summary.id },
            },
            {
              description: "Start another guided import.",
              href: "/imports/new" as const,
              icon: UploadCloud,
              label: "Import another file",
              search: { projectId: summary.project_id },
            },
          ].map(({ description, href, icon: Icon, label, search }) => (
            <Link
              className="group flex items-center gap-3 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-3 text-sm transition-colors hover:border-[var(--vpw-border-strong)] hover:bg-[var(--vpw-bg-panel)]"
              key={label}
              search={search}
              to={href}
            >
              <Icon aria-hidden="true" className="size-4 shrink-0 text-[var(--vpw-text-primary)]" />
              <span className="min-w-0 flex-1">
                <span className="block font-semibold text-[var(--vpw-text-primary)]">
                  {label}
                </span>
                <span className="block text-sm text-[var(--vpw-text-secondary)]">
                  {description}
                </span>
              </span>
              <ChevronRight
                aria-hidden="true"
                className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-hover:translate-x-0.5"
              />
            </Link>
          ))}
        </div>
      </VpwPanel>
      {summary.status === "failed" ? (
        <VpwStatusBanner title="Import failed" tone="critical">
          {failedRunCause(run, summary)}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}

function booleanLabel(value: boolean | null | undefined) {
  if (typeof value !== "boolean") return null
  return value ? "Yes" : "No"
}
