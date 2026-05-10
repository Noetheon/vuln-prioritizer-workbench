import { Link } from "@tanstack/react-router"
import { KeyRound, ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
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
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { SettingsTokenCreationResult } from "./SettingsTokenCreationResult"
import { activeTokenCount, buildApiTokenColumns } from "./settings-token-model"
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
        <VpwPanel className="flex flex-col gap-5 p-5">
          <VpwSectionHeader
            description="Select the least-privilege scopes required by the service account."
            eyebrow="Access"
            title="Service Token"
          />
          {tokenHasAdminScope ? (
            <VpwStatusBanner title="Admin scope is global" tone="warning">
              Admin tokens bypass the project boundary. Use only for trusted
              break-glass automation.
            </VpwStatusBanner>
          ) : null}
          <form className="flex flex-col gap-5" onSubmit={onCreateApiToken}>
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
                  const scopeId = `api-token-scope-${scope}`
                  return (
                    <label
                      className="block cursor-pointer"
                      htmlFor={scopeId}
                      key={scope}
                    >
                      <Checkbox
                        checked={checked}
                        className="peer sr-only"
                        id={scopeId}
                        onCheckedChange={() => onToggleApiTokenScope(scope)}
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

        <VpwPanel className="flex flex-col gap-5 p-5">
          <VpwSectionHeader
            description="Token secrets are masked by default and only available during the one-time creation response."
            eyebrow="One-time secret"
            title="Creation result"
          />
          <SettingsTokenCreationResult createdApiToken={createdApiToken} />
        </VpwPanel>
      </VpwGrid>

      <VpwPanel className="p-0">
        {activeTokens > 0 ? (
          <div className="border-b border-[var(--vpw-border-default)] p-4">
            <VpwStatusBanner title="Revocation is immediate" tone="warning">
              <span className="inline-flex items-center gap-2">
                <ShieldAlert aria-hidden="true" className="h-4 w-4" />
                Revoke tokens before deleting automation credentials or rotating
                project access.
              </span>
            </VpwStatusBanner>
          </div>
        ) : null}
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
