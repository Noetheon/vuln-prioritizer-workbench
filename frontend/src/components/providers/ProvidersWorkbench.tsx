import { Link } from "@tanstack/react-router"
import {
  Activity,
  Archive,
  Clock3,
  Database,
  FileArchive,
  GitBranch,
  ShieldCheck,
  Signal,
} from "lucide-react"

import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwChecksum,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwEvidenceFlowCard,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwProviderSnapshotCard,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  formatCacheAge,
  providerDataQualityNotes,
  providerSnapshotHealth,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceLabel,
  providerSourceState,
} from "@/lib/provider-format"

type ProvidersWorkbenchProps = {
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  onRefreshProviderStatus: () => void
}

type ProviderSourceRow = {
  cacheAge: string
  detail: string
  id: string
  lastUpdated: string
  name: string
  sourceType: string
  status: string
  tone: VpwBadgeTone
  usedInEvidence: string
  value: string
}

const fallbackProviderSources: ProviderSourceStatusPublic[] = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]

function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}

function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function sourceStatusLabel(source: ProviderSourceStatusPublic) {
  const state = providerSourceState(source)
  if (state === "available") {
    return source.last_sync || source.value ? "fresh" : "available"
  }
  return state
}

function sourceStatusTone(status: string): VpwBadgeTone {
  switch (status) {
    case "fresh":
    case "available":
      return "success"
    case "stale":
      return "warning"
    case "missing":
      return "critical"
    default:
      return "neutral"
  }
}

function providerHealthTone(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "info"
  }
  return providerStatus.status === "ok" ? "success" : "warning"
}

function evidenceReadinessTone(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "info"
  }
  if (providerStatus.last_error) {
    return "critical"
  }
  return providerStatus.status === "ok" ? "success" : "warning"
}

function sourceType(sourceName: string) {
  switch (sourceName.toLowerCase()) {
    case "nvd":
      return "Vulnerability database"
    case "epss":
      return "Exploit probability"
    case "kev":
      return "Known exploited"
    case "provider snapshot":
      return "Snapshot metadata"
    case "osv":
      return "Advisory database"
    default:
      return "Provider"
  }
}

function snapshotId(providerStatus: ProviderStatusPublic | null) {
  const metadata = objectRecord(providerStatus?.snapshot.source_metadata)
  return (
    stringValue(metadata.snapshot_id) ??
    providerStatus?.snapshot.id ??
    "No snapshot ID recorded"
  )
}

function selectedSources(providerStatus: ProviderStatusPublic | null) {
  const selected = providerStatus?.snapshot.selected_sources ?? []
  return selected.length > 0 ? selected.join(", ") : "No sources selected"
}

function sourceHashes(providerStatus: ProviderStatusPublic | null) {
  const hashes = providerStatus?.snapshot.source_hashes ?? {}
  const values = Object.entries(hashes).map(([source, hash]) =>
    typeof hash === "string" && hash.trim()
      ? `${source}: ${hash}`
      : `${source}: N.A.`,
  )
  return values.length > 0 ? values.join(" | ") : "No source hashes recorded"
}

function sourceRows(
  providerStatus: ProviderStatusPublic | null,
): ProviderSourceRow[] {
  const rows = (providerStatus?.sources ?? fallbackProviderSources).map(
    (source) => {
      const status = sourceStatusLabel(source)
      return {
        cacheAge: formatCacheAge(source.cache_age_seconds),
        detail: providerSourceDetail(source),
        id: source.name,
        lastUpdated: formatDateTime(source.last_sync),
        name: providerSourceLabel(source),
        sourceType: sourceType(source.name),
        status,
        tone: sourceStatusTone(status),
        usedInEvidence: source.selected ? "Yes" : "No",
        value: source.value ?? "N.A.",
      }
    },
  )

  rows.push({
    cacheAge: formatCacheAge(providerStatus?.cache_age_seconds),
    detail: providerSnapshotSummary(providerStatus),
    id: "provider-snapshot",
    lastUpdated: formatDateTime(
      providerStatus?.snapshot.generated_at ??
        providerStatus?.snapshot.created_at ??
        providerStatus?.last_sync,
    ),
    name: "PROVIDER SNAPSHOT",
    sourceType: "Snapshot metadata",
    status: providerStatus?.snapshot.missing
      ? "missing"
      : providerStatus?.status === "ok"
        ? "fresh"
        : "stale",
    tone: providerStatus?.snapshot.missing
      ? "critical"
      : providerStatus?.status === "ok"
        ? "success"
        : "warning",
    usedInEvidence: providerStatus?.snapshot.selected_sources?.length
      ? "Yes"
      : "Recorded",
    value: providerStatus?.snapshot.mode ?? providerStatus?.snapshot_mode ?? "N.A.",
  })

  return rows
}

function dataQualityLabel(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.last_error) {
    return "Degraded"
  }
  if ((providerStatus.warnings ?? []).length > 0) {
    return "Warnings"
  }
  if ((providerStatus.sources ?? []).some((source) => !source.available)) {
    return "Gaps"
  }
  return "Usable"
}

function evidenceReadinessLabel(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "Checking"
  }
  return providerStatus.last_error ? "Needs attention" : "Evidence ready"
}

export function ProvidersWorkbench({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
}: ProvidersWorkbenchProps) {
  const rows = sourceRows(providerStatus)
  const availableSources = rows.filter((row) =>
    ["available", "fresh"].includes(row.status),
  ).length
  const staleSources = rows.filter((row) => row.status === "stale").length
  const missingSources = rows.filter((row) => row.status === "missing").length
  const dataQuality = dataQualityLabel(providerStatus)
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)
  const snapshotChecksum =
    providerStatus?.snapshot.content_hash ?? "No content hash recorded"

  const columns: readonly VpwDataTableColumn<ProviderSourceRow>[] = [
    {
      cell: (row) => (
        <div className="min-w-40">
          <p className="font-semibold text-[var(--vpw-text-primary)]">
            {row.name}
          </p>
          <p className="text-xs text-[var(--vpw-text-muted)]">{row.detail}</p>
        </div>
      ),
      header: "Source",
      id: "source",
    },
    {
      cell: (row) => <VpwBadge tone={row.tone}>{row.status}</VpwBadge>,
      header: "Status",
      id: "status",
    },
    {
      cell: (row) => row.lastUpdated,
      header: "Last updated",
      id: "last-updated",
    },
    {
      cell: (row) => row.cacheAge,
      header: "Cache age",
      id: "cache-age",
    },
    {
      cell: (row) => row.sourceType,
      header: "Source type",
      id: "source-type",
    },
    {
      cell: (row) => (
        <VpwBadge tone={row.usedInEvidence === "No" ? "neutral" : "info"}>
          {row.usedInEvidence}
        </VpwBadge>
      ),
      header: "Used in evidence",
      id: "used-in-evidence",
    },
    {
      cell: () => (
        <Button
          onClick={onRefreshProviderStatus}
          size="sm"
          type="button"
          variant="outline"
        >
          Refresh
        </Button>
      ),
      header: "Actions",
      id: "actions",
    },
  ]

  const snapshotSources = rows.map((row) => ({
    name: row.name,
    status: row.status,
    tone: row.tone,
  }))

  const evidenceFlowItems = [
    {
      description: "NVD, EPSS and KEV context is read from the stored source state.",
      meta: `${availableSources} available`,
      title: "Provider sources",
      tone: missingSources > 0 ? "warning" : "success",
    },
    {
      description: providerStatus?.snapshot.locked_provider_data
        ? "Locked snapshot mode is active for reproducible evidence."
        : "Stored provider data is available for evidence generation.",
      meta: providerStatus?.snapshot_mode ?? "missing",
      title: "Snapshot mode",
      tone: providerStatus?.status === "ok" ? "success" : "warning",
    },
    {
      description: "Provider data is included in evidence bundles and executive reports.",
      meta: evidenceReadiness,
      title: "Evidence connection",
      tone: providerStatus?.last_error ? "critical" : "success",
    },
  ] as const

  return (
    <VpwPageContainer className="space-y-6 px-0 py-0">
      <VpwSection>
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Monitor vulnerability intelligence sources, snapshot freshness and evidence data quality."
            eyebrow="Provider intelligence"
            title="Providers"
          />
          <VpwToolbar label="Provider actions">
            <VpwToolbarGroup>
              <Button
                aria-busy={providerStatusLoading}
                className="disabled:bg-[var(--vpw-blue)] disabled:text-white disabled:opacity-100"
                disabled={providerStatusLoading}
                onClick={onRefreshProviderStatus}
                type="button"
              >
                <Activity aria-hidden="true" />
                Refresh providers
              </Button>
              <Button asChild variant="outline">
                <Link to="/reports">View Evidence Center</Link>
              </Button>
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <VpwBadge tone={providerHealthTone(providerStatus)}>
                Snapshot mode: {providerStatus?.snapshot_mode ?? "missing"}
              </VpwBadge>
              <VpwBadge tone="neutral">
                Last sync: {formatDateTime(providerStatus?.last_sync)}
              </VpwBadge>
              <VpwBadge tone={providerHealthTone(providerStatus)}>
                Provider health: {providerSnapshotHealth(providerStatus)}
              </VpwBadge>
              <VpwBadge tone={evidenceReadinessTone(providerStatus)}>
                Evidence: {evidenceReadiness}
              </VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
        </VpwPanel>
      </VpwSection>

      {providerStatusError ? (
        <VpwStatusBanner title="Provider data unavailable" tone="critical">
          {providerStatusError}
        </VpwStatusBanner>
      ) : null}

      {providerStatusLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : null}

      <VpwGrid columns={1} className="md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <VpwMetricCard
          description={providerSnapshotSummary(providerStatus)}
          icon={<Signal aria-hidden="true" />}
          label="Provider health"
          tone={providerHealthTone(providerStatus)}
          value={providerSnapshotHealth(providerStatus)}
        />
        <VpwMetricCard
          description={
            providerStatus?.snapshot.locked_provider_data
              ? "Locked replay evidence"
              : "Stored provider evidence"
          }
          icon={<Archive aria-hidden="true" />}
          label="Snapshot mode"
          tone={providerStatus?.snapshot.locked_provider_data ? "support" : "info"}
          value={providerStatus?.snapshot_mode ?? "missing"}
        />
        <VpwMetricCard
          description="Latest provider snapshot update"
          icon={<Clock3 aria-hidden="true" />}
          label="Last sync"
          value={formatDateTime(providerStatus?.last_sync)}
        />
        <VpwMetricCard
          description="Age of stored provider cache"
          icon={<Database aria-hidden="true" />}
          label="Cache age"
          value={formatCacheAge(providerStatus?.cache_age_seconds)}
        />
        <VpwMetricCard
          description={`${missingSources} missing, ${staleSources} stale`}
          icon={<ShieldCheck aria-hidden="true" />}
          label="Data quality"
          tone={missingSources > 0 ? "warning" : "success"}
          value={dataQuality}
        />
        <VpwMetricCard
          description="Provider data for reports"
          icon={<FileArchive aria-hidden="true" />}
          label="Evidence readiness"
          tone={evidenceReadinessTone(providerStatus)}
          value={evidenceReadiness}
        />
      </VpwGrid>

      <VpwSection>
        <VpwSectionHeader
          description="Configured vulnerability intelligence sources and whether they are available for prioritization evidence."
          eyebrow="Source inventory"
          title="Provider sources"
        />
        {rows.length === 0 && !providerStatusLoading ? (
          <VpwEmptyState
            icon={<Database aria-hidden="true" />}
            title="No provider sources recorded"
            description="Refresh provider status to load the latest stored source state."
            action={
              <Button onClick={onRefreshProviderStatus} type="button">
                Refresh providers
              </Button>
            }
          />
        ) : (
          <VpwDataTable
            caption="Provider sources"
            columns={columns}
            data={rows}
            density="compact"
            getRowKey={(row) => row.id}
          />
        )}
      </VpwSection>

      <VpwGrid columns={2}>
        <VpwProviderSnapshotCard
          onRefresh={onRefreshProviderStatus}
          refreshLabel="Refresh providers"
          snapshotId={snapshotId(providerStatus)}
          sources={snapshotSources}
        />

        <VpwPanel className="space-y-4 p-5">
          <VpwSectionHeader
            description="Snapshot metadata used to make evidence bundles reproducible."
            eyebrow="Snapshot details"
            title="Recorded snapshot"
          />
          <VpwChecksum
            label="Content hash"
            value={snapshotChecksum}
            verified={Boolean(providerStatus?.snapshot.content_hash)}
          />
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Snapshot ID",
                value: snapshotId(providerStatus),
              },
              {
                label: "Mode",
                value: providerStatus?.snapshot.mode ?? "missing",
                tone: providerStatus?.snapshot.locked_provider_data
                  ? "support"
                  : "info",
              },
              {
                label: "Generated",
                value: formatDateTime(
                  providerStatus?.snapshot.generated_at ??
                    providerStatus?.snapshot.created_at,
                ),
              },
              {
                label: "Requested CVEs",
                value: providerStatus?.snapshot.requested_cves ?? 0,
              },
              {
                label: "Selected sources",
                value: selectedSources(providerStatus),
              },
              {
                label: "Source path",
                value: providerStatus?.snapshot.source_path ?? "N.A.",
              },
              {
                label: "NVD last sync",
                value: formatDateTime(providerStatus?.snapshot.nvd_last_sync),
              },
              {
                label: "EPSS date",
                value: providerStatus?.snapshot.epss_date ?? "N.A.",
              },
              {
                label: "KEV catalog",
                value: providerStatus?.snapshot.kev_catalog_version ?? "N.A.",
              },
              {
                label: "Source hashes",
                value: sourceHashes(providerStatus),
              },
            ]}
          />
        </VpwPanel>
      </VpwGrid>

      <VpwGrid columns={2}>
        <VpwPanel className="space-y-4 p-5">
          <VpwSectionHeader
            description="Structured trust notes for prioritization and reporting."
            eyebrow="Data quality"
            title="Provider data quality notes"
          />
          <div className="space-y-3">
            <VpwStatusBanner title="CVSS coverage" tone="info">
              Missing CVSS does not mean low risk; it is a provider data gap.
            </VpwStatusBanner>
            <VpwStatusBanner title="EPSS coverage" tone="warning">
              Missing EPSS should be treated as incomplete exploit-probability
              evidence, not as zero likelihood.
            </VpwStatusBanner>
            <VpwStatusBanner title="KEV signal" tone="critical">
              KEV is a strong prioritization signal when present.
            </VpwStatusBanner>
            <VpwStatusBanner title="Locked snapshots" tone="success">
              Locked snapshots are used for reproducible evidence bundles and
              executive reports.
            </VpwStatusBanner>
            {providerDataQualityNotes(providerStatus).map((note) => (
              <VpwStatusBanner key={note} title="Snapshot note" tone="info">
                {note}
              </VpwStatusBanner>
            ))}
            {(providerStatus?.warnings ?? []).map((warning) => (
              <VpwStatusBanner key={warning} title="Provider warning" tone="warning">
                {warning}
              </VpwStatusBanner>
            ))}
            {providerStatus?.last_error ? (
              <VpwStatusBanner title="Last provider error" tone="critical">
                {providerStatus.last_error}
              </VpwStatusBanner>
            ) : null}
          </div>
        </VpwPanel>

        <div className="space-y-4">
          <VpwEvidenceFlowCard items={evidenceFlowItems} />
          <VpwPanel className="space-y-4 p-5">
            <VpwSectionHeader
              description="Latest provider update-job state from the existing provider status response."
              eyebrow="Update job"
              title="Latest provider update"
            />
            {providerStatus?.latest_update_job ? (
              <VpwKeyValueList
                columns={2}
                items={[
                  {
                    label: "Job ID",
                    value: providerStatus.latest_update_job.id,
                  },
                  {
                    label: "Status",
                    value: providerStatus.latest_update_job.status,
                    tone:
                      providerStatus.latest_update_job.status === "failed"
                        ? "critical"
                        : "info",
                  },
                  {
                    label: "Requested sources",
                    value:
                      providerStatus.latest_update_job.requested_sources?.join(
                        ", ",
                      ) ?? "N.A.",
                  },
                  {
                    label: "Started",
                    value: formatDateTime(
                      providerStatus.latest_update_job.started_at,
                    ),
                  },
                  {
                    label: "Finished",
                    value: formatDateTime(
                      providerStatus.latest_update_job.finished_at,
                    ),
                  },
                  {
                    label: "Error",
                    value:
                      providerStatus.latest_update_job.error_message ?? "None",
                  },
                ]}
              />
            ) : (
              <VpwEmptyState
                icon={<GitBranch aria-hidden="true" />}
                title="No provider update job recorded"
                description="The current provider status response has no update-job history."
              />
            )}
            <VpwProgress
              label="Evidence readiness"
              tone={evidenceReadinessTone(providerStatus)}
              value={providerStatus?.last_error ? 35 : providerStatus ? 86 : 20}
            />
          </VpwPanel>
        </div>
      </VpwGrid>
    </VpwPageContainer>
  )
}
