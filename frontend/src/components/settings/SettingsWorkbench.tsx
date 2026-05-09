import { Link } from "@tanstack/react-router"
import { Database, KeyRound, ShieldCheck, UserRound } from "lucide-react"
import type { FormEvent } from "react"

import type {
  ApiTokenCreatePublic,
  ApiTokenPublic,
  ProjectPublic,
  ProviderStatusPublic,
  UserPublic,
  WorkbenchStatus,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwCodeBlock,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwField,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import {
  type ApiTokenScope,
  activeTokenCount,
  buildApiTokenColumns,
  formatDateTime,
  formatScopes,
  tokenActivityPercent,
} from "./settings-token-model"

export type SettingsWorkbenchProps = {
  apiTokenActionLoading: boolean
  apiTokenError: string
  apiTokenMessage: string
  apiTokenName: string
  apiTokenProjectId: string
  apiTokenProjectOptions: readonly ProjectPublic[]
  apiTokenScopeOptions: readonly ApiTokenScope[]
  apiTokenScopes: readonly ApiTokenScope[]
  apiTokens: readonly ApiTokenPublic[]
  apiTokensLoading: boolean
  createdApiToken: ApiTokenCreatePublic | null
  currentUser: UserPublic | null
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  status: WorkbenchStatus | null
  statusError: string
  onApiTokenNameChange: (value: string) => void
  onApiTokenProjectChange: (value: string) => void
  onCreateApiToken: (event: FormEvent<HTMLFormElement>) => void | Promise<void>
  onRevokeApiToken: (token: ApiTokenPublic) => void | Promise<void>
  onToggleApiTokenScope: (scope: ApiTokenScope) => void
}

type ProviderConfigRow = {
  id: string
  setting: string
  value: string
  detail: string
  tone: VpwBadgeTone
}

function userLabel(user: UserPublic | null) {
  return user?.email ?? "Loading user"
}

function sourceByName(
  providerStatus: ProviderStatusPublic | null,
  sourceName: string,
) {
  return (providerStatus?.sources ?? []).find(
    (source) => source.name.toLowerCase() === sourceName,
  )
}

function sourceAvailability(
  providerStatus: ProviderStatusPublic | null,
  sourceName: string,
) {
  const source = sourceByName(providerStatus, sourceName)
  if (!source) {
    return { label: "Not reported", tone: "neutral" as VpwBadgeTone }
  }
  if (source.stale) {
    return { label: "Stale", tone: "warning" as VpwBadgeTone }
  }
  return source.available
    ? { label: "Available", tone: "success" as VpwBadgeTone }
    : { label: "Missing", tone: "critical" as VpwBadgeTone }
}

function providerHealth(providerStatus: ProviderStatusPublic | null) {
  if (!providerStatus) {
    return { label: "Loading", tone: "info" as VpwBadgeTone }
  }
  return providerStatus.status === "ok"
    ? { label: "Healthy", tone: "success" as VpwBadgeTone }
    : { label: "Review", tone: "warning" as VpwBadgeTone }
}

function evidenceReadiness(
  providerStatus: ProviderStatusPublic | null,
  providerStatusError: string,
  statusError: string,
) {
  if (providerStatusError || statusError || providerStatus?.last_error) {
    return { label: "Needs review", tone: "critical" as VpwBadgeTone }
  }
  if (!providerStatus) {
    return { label: "Checking", tone: "info" as VpwBadgeTone }
  }
  return providerStatus.status === "ok"
    ? { label: "Ready", tone: "success" as VpwBadgeTone }
    : { label: "Partial", tone: "warning" as VpwBadgeTone }
}

function safeDiagnosticsCode({
  providerStatus,
  status,
  statusError,
}: {
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}) {
  return JSON.stringify(
    {
      app: status?.app ?? "unavailable",
      backendStatus: status?.status ?? "unavailable",
      corePackage: status?.core_package ?? "unavailable",
      coreVersion: status?.core_version ?? "unavailable",
      databaseStatus: status?.database_status ?? "unavailable",
      schemaStatus: status?.schema_status ?? "unavailable",
      providerStatus: providerStatus?.status ?? "unavailable",
      providerSnapshotMode: providerStatus?.snapshot_mode ?? "unavailable",
      providerSourceCount: providerStatus?.sources?.length ?? 0,
      statusError: statusError || null,
    },
    null,
    2,
  )
}

function providerConfigRows(
  providerStatus: ProviderStatusPublic | null,
): ProviderConfigRow[] {
  const nvd = sourceAvailability(providerStatus, "nvd")
  const epss = sourceAvailability(providerStatus, "epss")
  const kev = sourceAvailability(providerStatus, "kev")

  return [
    {
      id: "nvd",
      setting: "NVD source",
      value: nvd.label,
      detail:
        "Availability is reported by the backend without exposing provider secrets.",
      tone: nvd.tone,
    },
    {
      id: "epss",
      setting: "EPSS provider",
      value: epss.label,
      detail: "Exploit probability source used for prioritization.",
      tone: epss.tone,
    },
    {
      id: "kev",
      setting: "KEV provider",
      value: kev.label,
      detail: "Known Exploited Vulnerabilities signal used for evidence.",
      tone: kev.tone,
    },
    {
      id: "snapshot-mode",
      setting: "Snapshot mode",
      value: providerStatus?.snapshot_mode ?? "Not reported",
      detail: providerSnapshotSummary(providerStatus),
      tone: providerStatus?.snapshot_mode ? "info" : "neutral",
    },
    {
      id: "cache-age",
      setting: "Cache age",
      value: formatCacheAge(providerStatus?.cache_age_seconds),
      detail: "Provider cache age reported by the Workbench backend.",
      tone: providerStatus?.cache_age_seconds ? "info" : "neutral",
    },
    {
      id: "upload-size",
      setting: "Max upload size",
      value: "Not exposed",
      detail:
        "The current settings API does not publish upload limit metadata.",
      tone: "neutral",
    },
  ]
}

export function SettingsWorkbench({
  apiTokenActionLoading,
  apiTokenError,
  apiTokenMessage,
  apiTokenName,
  apiTokenProjectId,
  apiTokenProjectOptions,
  apiTokenScopeOptions,
  apiTokenScopes,
  apiTokens,
  apiTokensLoading,
  createdApiToken,
  currentUser,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  status,
  statusError,
  onApiTokenNameChange,
  onApiTokenProjectChange,
  onCreateApiToken,
  onRevokeApiToken,
  onToggleApiTokenScope,
}: SettingsWorkbenchProps) {
  const activeTokens = activeTokenCount(apiTokens)
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )
  const providerRows = providerConfigRows(providerStatus)
  const tokenHasAdminScope = apiTokenScopes.includes("admin")

  const tokenColumns = buildApiTokenColumns({
    actionLoading: apiTokenActionLoading,
    projects: apiTokenProjectOptions,
    onRevokeApiToken,
  })

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

  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <VpwSection aria-label="User Settings">
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            actions={
              <Button asChild variant="outline">
                <Link to="/providers">View providers</Link>
              </Button>
            }
            description="Manage workspace access, API tokens, runtime configuration and diagnostics."
            eyebrow="Workspace configuration"
            title="Settings"
          />
          <VpwToolbar label="Settings context">
            <VpwToolbarGroup>
              <VpwBadge tone={currentUser ? "success" : "warning"}>
                {userLabel(currentUser)}
              </VpwBadge>
              <VpwBadge tone={apiTokens.length > 0 ? "info" : "neutral"}>
                API tokens: {apiTokens.length}
              </VpwBadge>
              <VpwBadge tone={provider.tone}>
                Snapshot: {providerStatus?.snapshot_mode ?? "loading"}
              </VpwBadge>
              <VpwBadge tone={evidence.tone}>
                Evidence: {evidence.label}
              </VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
        </VpwPanel>
      </VpwSection>

      {statusError ? (
        <VpwStatusBanner title="Workbench status unavailable" tone="critical">
          {statusError}
        </VpwStatusBanner>
      ) : null}

      {providerStatusError ? (
        <VpwStatusBanner title="Provider status unavailable" tone="warning">
          {providerStatusError}
        </VpwStatusBanner>
      ) : null}

      {apiTokenError ? (
        <VpwStatusBanner title="API token action failed" tone="critical">
          {apiTokenError}
        </VpwStatusBanner>
      ) : null}

      {apiTokenMessage ? (
        <VpwStatusBanner title="API token action complete" tone="success">
          {apiTokenMessage}
        </VpwStatusBanner>
      ) : null}

      <VpwGrid columns={4}>
        <VpwMetricCard
          description={
            currentUser?.email ??
            (currentUser?.is_active ? "Session active" : "Checking account")
          }
          icon={<UserRound aria-hidden="true" className="h-5 w-5" />}
          label="Signed-in user"
          tone={currentUser?.is_active ? "success" : "warning"}
          value={currentUser ? "Authenticated" : "Loading"}
        />
        <VpwMetricCard
          description={`${activeTokens} active`}
          icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
          label="API tokens"
          tone={apiTokens.length > 0 ? "info" : "neutral"}
          value={apiTokensLoading ? "Loading" : apiTokens.length}
        />
        <VpwMetricCard
          description={providerSnapshotSummary(providerStatus)}
          icon={<Database aria-hidden="true" className="h-5 w-5" />}
          label="Provider snapshot"
          tone={provider.tone}
          value={provider.label}
        />
        <VpwMetricCard
          description={
            providerStatus?.last_sync
              ? `Last sync ${formatDateTime(providerStatus.last_sync)}`
              : "No sync timestamp"
          }
          icon={<ShieldCheck aria-hidden="true" className="h-5 w-5" />}
          label="Evidence readiness"
          tone={evidence.tone}
          value={evidence.label}
        />
      </VpwGrid>

      <VpwGrid columns={2}>
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Current authenticated account and workspace runtime state."
            title="Account and session"
          />
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Signed-in user",
                value: currentUser?.email ?? "Loading user",
              },
              {
                label: "Session state",
                value: currentUser ? "Authenticated" : "Loading",
                tone: currentUser ? "success" : "warning",
              },
              {
                label: "Workspace mode",
                value: status?.app ?? "Workbench",
              },
              {
                label: "Auth mode",
                value: currentUser?.is_superuser
                  ? "Admin session"
                  : "User session",
                tone: currentUser?.is_superuser ? "support" : "info",
              },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Token inventory, provider health, and reproducibility signals."
            title="Setup health"
          />
          {providerStatusLoading ? (
            <VpwSkeletonStack rows={4} />
          ) : (
            <VpwKeyValueList
              columns={2}
              items={[
                {
                  label: "Backend status",
                  value: status?.status ?? "Not reported",
                  tone: status?.status === "ready" ? "success" : "neutral",
                },
                {
                  label: "Provider health",
                  value: provider.label,
                  tone: provider.tone,
                },
                {
                  label: "Cache age",
                  value: formatCacheAge(providerStatus?.cache_age_seconds),
                },
                {
                  label: "Latest API error",
                  value:
                    providerStatus?.last_error ||
                    providerStatusError ||
                    statusError ||
                    "None",
                  tone:
                    providerStatus?.last_error ||
                    providerStatusError ||
                    statusError
                      ? "critical"
                      : "success",
                },
              ]}
            />
          )}
          <VpwProgress
            label="Active token coverage"
            tone={apiTokens.length > 0 ? "info" : "neutral"}
            value={tokenActivityPercent(apiTokens)}
          />
        </VpwPanel>
      </VpwGrid>

      <VpwSection aria-label="API tokens">
        <VpwSectionHeader
          actions={
            <VpwBadge tone={activeTokens > 0 ? "success" : "neutral"}>
              Active tokens: {activeTokens}
            </VpwBadge>
          }
          description="Create service tokens for automation and revoke tokens that should no longer access the Workbench."
          title="API tokens"
        />
        <VpwGrid columns={2}>
          <VpwPanel className="space-y-5 p-5">
            <VpwSectionHeader
              description="Select the least-privilege scopes required by the service account."
              eyebrow="Access"
              title="Service Token"
            />
            <form className="space-y-5" onSubmit={onCreateApiToken}>
              <VpwField
                description="Use a short automation or integration name."
                htmlFor="api-token-name"
                label="Name"
                required
              >
                <Input
                  id="api-token-name"
                  maxLength={200}
                  onChange={(event) => onApiTokenNameChange(event.target.value)}
                  value={apiTokenName}
                />
              </VpwField>

              <VpwField label="Scopes" required>
                <div className="grid gap-3 sm:grid-cols-2">
                  {apiTokenScopeOptions.map((scope) => {
                    const checked = apiTokenScopes.includes(scope)
                    return (
                      <label className="block cursor-pointer" key={scope}>
                        <input
                          checked={checked}
                          className="peer sr-only"
                          onChange={() => onToggleApiTokenScope(scope)}
                          type="checkbox"
                        />
                        <VpwSelectionCard
                          as="span"
                          checked={checked}
                          className="cursor-pointer peer-focus-visible:ring-2 peer-focus-visible:ring-[var(--vpw-blue)] peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-[var(--vpw-bg-default)]"
                          meta={scope === "admin" ? "Privileged" : "Service"}
                          title={scope.toUpperCase()}
                        >
                          {scope === "read"
                            ? "Read workbench findings and evidence metadata."
                            : scope === "import"
                              ? "Create import runs and normalize supplied inputs."
                              : scope === "report"
                                ? "Generate and download report artifacts."
                                : "Administrative API access for trusted operators."}
                        </VpwSelectionCard>
                      </label>
                    )
                  })}
                </div>
              </VpwField>

              <VpwField
                description={
                  tokenHasAdminScope
                    ? "Admin tokens are global."
                    : "Required project boundary for service tokens."
                }
                htmlFor="api-token-project"
                label="Project scope"
                required={!tokenHasAdminScope}
              >
                <Select
                  disabled={tokenHasAdminScope || apiTokenProjectOptions.length === 0}
                  onValueChange={onApiTokenProjectChange}
                  value={apiTokenProjectId}
                >
                  <SelectTrigger id="api-token-project">
                    <SelectValue placeholder="Select project" />
                  </SelectTrigger>
                  <SelectContent>
                    {apiTokenProjectOptions.map((project) => (
                      <SelectItem key={project.id} value={project.id}>
                        {project.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </VpwField>

              <Button
                aria-busy={apiTokenActionLoading}
                disabled={
                  apiTokenActionLoading ||
                  (!tokenHasAdminScope && apiTokenProjectOptions.length === 0)
                }
                type="submit"
              >
                {apiTokenActionLoading ? "Creating" : "Create Token"}
              </Button>
            </form>
          </VpwPanel>

          <VpwPanel className="space-y-5 p-5">
            <VpwSectionHeader
              description="Token secrets are only shown in the one-time creation response."
              eyebrow="One-time secret"
              title="Creation result"
            />
            {createdApiToken ? (
              <section aria-label="Created API token" className="space-y-4">
                <VpwStatusBanner
                  title={`Token ${createdApiToken.name} created`}
                  tone="success"
                >
                  Save this one-time token now. It will be cleared when you
                  leave Settings and is not listed again.
                </VpwStatusBanner>
                <VpwField htmlFor="created-token-value" label="Token">
                  <Input
                    className="font-mono"
                    id="created-token-value"
                    onFocus={(event) => event.currentTarget.select()}
                    readOnly
                    value={createdApiToken.token}
                  />
                </VpwField>
                <VpwKeyValueList
                  columns={2}
                  items={[
                    {
                      label: "Scopes",
                      value: formatScopes(createdApiToken.scopes),
                      tone: "support",
                    },
                    {
                      label: "Created",
                      value: formatDateTime(createdApiToken.created_at),
                    },
                    {
                      label: "Expires",
                      value: formatDateTime(createdApiToken.expires_at),
                    },
                  ]}
                />
              </section>
            ) : (
              <VpwEmptyState
                description="Create a token to receive a one-time cleartext value. Existing tokens are shown below without secrets."
                icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
                title="No new token created"
              />
            )}
          </VpwPanel>
        </VpwGrid>

        <VpwPanel className="p-0">
          {apiTokensLoading ? (
            <div className="p-5">
              <VpwSkeletonStack rows={6} />
            </div>
          ) : (
            <VpwDataTable
              caption="API tokens table"
              columns={tokenColumns}
              data={apiTokens}
              density="compact"
              emptyState={
                <VpwEmptyState
                  action={
                    <Button asChild variant="outline">
                      <Link to="/findings">View findings</Link>
                    </Button>
                  }
                  description="Create a token when automation needs scoped access to Workbench APIs."
                  icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
                  title="No API tokens yet"
                />
              }
              getRowKey={(token) => token.id}
            />
          )}
        </VpwPanel>
      </VpwSection>

      <VpwGrid columns={2}>
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Safe runtime and provider configuration values reported by existing APIs."
            title="Provider and runtime configuration"
          />
          <VpwDataTable
            caption="Provider runtime configuration"
            columns={providerColumns}
            data={providerRows}
            density="compact"
            getRowKey={(row) => row.id}
          />
          <VpwStatusBanner title="Secrets are not displayed" tone="info">
            Provider keys, environment secrets, and stored token secrets are not
            rendered in Settings. Use environment variables for provider keys.
          </VpwStatusBanner>
        </VpwPanel>

        <VpwPanel className="space-y-5 p-5">
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
          <VpwStatusBanner
            title="Generated client stays managed"
            tone="warning"
          >
            API contracts are consumed through the generated client and should
            not be edited by hand.
          </VpwStatusBanner>
        </VpwPanel>
      </VpwGrid>

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
    </VpwPageContainer>
  )
}
