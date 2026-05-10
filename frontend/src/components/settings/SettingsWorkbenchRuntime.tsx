import type { ProviderStatusPublic, WorkbenchStatus } from "@/api-client"
import {
  VpwBadge,
  VpwCodeBlock,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { providerSnapshotSummary } from "@/lib/provider-format"
import {
  evidenceReadiness,
  type ProviderConfigRow,
  providerConfigRows,
  type SettingsWorkbenchProps,
  safeDiagnosticsCode,
} from "./settings-workbench-model"

type SettingsRuntimeDiagnosticsProps = Pick<
  SettingsWorkbenchProps,
  "providerStatus" | "providerStatusError" | "status" | "statusError"
>

const providerColumns: VpwDataTableColumn<ProviderConfigRow>[] = [
  {
    id: "setting",
    header: "Setting",
    cell: (row) => (
      <p className="font-medium text-[var(--vpw-text-primary)]">
        {row.setting}
      </p>
    ),
  },
  {
    id: "value",
    header: "Value",
    cell: (row) => <VpwBadge tone={row.tone}>{row.value}</VpwBadge>,
  },
  {
    id: "detail",
    header: "Details",
    cell: (row) => (
      <span className="text-sm text-[var(--vpw-text-secondary)]">
        {row.detail}
      </span>
    ),
  },
]

function ProviderRuntimeConfiguration({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Safe runtime and provider configuration values reported by existing APIs."
        title="Provider and runtime configuration"
      />
      <VpwDataTable
        caption="Provider runtime configuration"
        columns={providerColumns}
        data={providerConfigRows(providerStatus)}
        density="compact"
        getRowKey={(row) => row.id}
      />
      <VpwStatusBanner title="Secrets are not displayed" tone="info">
        Provider keys, environment secrets, and stored token secrets are not
        rendered in Settings. Use environment variables for provider keys.
      </VpwStatusBanner>
    </VpwPanel>
  )
}

function DiagnosticsPanel({
  evidence,
  providerStatus,
  status,
  statusError,
}: {
  evidence: ReturnType<typeof evidenceReadiness>
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}) {
  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Compact troubleshooting facts for support and evidence checks."
        title="Diagnostics"
      />
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Frontend",
            value: "Vite app",
          },
          {
            label: "Backend version",
            value: status?.core_version ?? "Not reported",
          },
          {
            label: "Provider freshness",
            value: providerSnapshotSummary(providerStatus),
          },
          {
            label: "Evidence readiness",
            value: evidence.label,
            tone: evidence.tone,
          },
        ]}
      />
      <VpwCodeBlock
        code={safeDiagnosticsCode({ providerStatus, status, statusError })}
        label="Safe diagnostics"
      />
      <VpwStatusBanner title="Generated client stays managed" tone="warning">
        API contracts are consumed through the generated client and should not
        be edited by hand.
      </VpwStatusBanner>
    </VpwPanel>
  )
}

export function SettingsRuntimeDiagnostics({
  providerStatus,
  providerStatusError,
  status,
  statusError,
}: SettingsRuntimeDiagnosticsProps) {
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )

  return (
    <VpwGrid columns={2}>
      <ProviderRuntimeConfiguration providerStatus={providerStatus} />
      <DiagnosticsPanel
        evidence={evidence}
        providerStatus={providerStatus}
        status={status}
        statusError={statusError}
      />
    </VpwGrid>
  )
}

export function SettingsSecurityNotes() {
  return (
    <VpwSection>
      <VpwSectionHeader
        description="Operational guardrails for access and troubleshooting."
        title="Security notes"
      />
      <VpwGrid columns={3}>
        <VpwStatusBanner title="Do not share API tokens" tone="critical">
          Treat service tokens like passwords and revoke unused tokens.
        </VpwStatusBanner>
        <VpwStatusBanner title="Accepted diagnostics only" tone="info">
          Diagnostics show status and version metadata, not provider secrets.
        </VpwStatusBanner>
        <VpwStatusBanner title="Evidence remains reproducible" tone="success">
          Provider snapshot state is visible so generated reports can explain
          their data sources.
        </VpwStatusBanner>
      </VpwGrid>
    </VpwSection>
  )
}
