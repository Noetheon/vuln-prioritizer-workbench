import { Link } from "@tanstack/react-router"
import { KeyRound } from "lucide-react"

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
  VpwDataTable,
  VpwEmptyState,
  VpwField,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  activeTokenCount,
  buildApiTokenColumns,
  formatDateTime,
  formatScopes,
} from "./settings-token-model"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsApiTokensSectionProps = Pick<
  SettingsWorkbenchProps,
  | "apiTokenActionLoading"
  | "apiTokenName"
  | "apiTokenProjectId"
  | "apiTokenProjectOptions"
  | "apiTokenScopeOptions"
  | "apiTokenScopes"
  | "apiTokens"
  | "apiTokensLoading"
  | "createdApiToken"
  | "onApiTokenNameChange"
  | "onApiTokenProjectChange"
  | "onCreateApiToken"
  | "onRevokeApiToken"
  | "onToggleApiTokenScope"
>

export function SettingsApiTokensSection({
  apiTokenActionLoading,
  apiTokenName,
  apiTokenProjectId,
  apiTokenProjectOptions,
  apiTokenScopeOptions,
  apiTokenScopes,
  apiTokens,
  apiTokensLoading,
  createdApiToken,
  onApiTokenNameChange,
  onApiTokenProjectChange,
  onCreateApiToken,
  onRevokeApiToken,
  onToggleApiTokenScope,
}: SettingsApiTokensSectionProps) {
  const activeTokens = activeTokenCount(apiTokens)
  const tokenHasAdminScope = apiTokenScopes.includes("admin")
  const tokenColumns = buildApiTokenColumns({
    actionLoading: apiTokenActionLoading,
    projects: apiTokenProjectOptions,
    onRevokeApiToken,
  })

  return (
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
                              : "Root-equivalent global access for trusted operators."}
                      </VpwSelectionCard>
                    </label>
                  )
                })}
              </div>
            </VpwField>

            <VpwField
              description={
                tokenHasAdminScope
                  ? "Admin tokens are root-equivalent and global."
                  : "Required project boundary for service tokens."
              }
              htmlFor="api-token-project"
              label="Project scope"
              required={!tokenHasAdminScope}
            >
              <Select
                disabled={
                  tokenHasAdminScope || apiTokenProjectOptions.length === 0
                }
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
                Save this one-time token now. It will be cleared when you leave
                Settings and is not listed again.
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
  )
}
