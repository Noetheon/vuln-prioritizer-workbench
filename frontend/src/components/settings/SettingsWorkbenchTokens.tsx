import { KeyRound, Plus, ShieldAlert } from "lucide-react"
import { useEffect, useState } from "react"

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
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  VpwBadge,
  VpwDataTable,
  VpwEmptyState,
  VpwField,
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
  | "onClearCreatedApiToken"
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
  onClearCreatedApiToken,
  onCreateApiToken,
  onRevokeApiToken,
  onToggleApiTokenScope,
}: SettingsApiTokensSectionProps) {
  const [tokenSheetOpen, setTokenSheetOpen] = useState(false)
  const activeTokens = activeTokenCount(apiTokens)
  const tokenColumns = buildApiTokenColumns({
    actionLoading: apiTokenActionLoading,
    projects: apiTokenProjectOptions,
    onRevokeApiToken,
  })

  useEffect(() => {
    if (createdApiToken) {
      setTokenSheetOpen(true)
    }
  }, [createdApiToken])

  function handleTokenSheetOpenChange(open: boolean) {
    setTokenSheetOpen(open)
    if (!open) {
      onClearCreatedApiToken()
    }
  }

  return (
    <VpwSection aria-label="API tokens">
      <VpwPanel className="p-0">
        <div className="flex flex-col gap-4 border-b border-[var(--vpw-border-default)] bg-[color-mix(in_srgb,var(--vpw-bg-panel)_52%,var(--vpw-bg-card))] p-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <p className="vpw-label">Token inventory</p>
            <h2 className="mt-1 text-xl font-semibold tracking-[-0.01em] text-[var(--vpw-text-primary)]">
              API tokens
            </h2>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
              Existing tokens are shown without secrets. Create new secrets only
              when automation needs scoped Workbench API access.
            </p>
            {activeTokens > 0 ? (
              <div className="mt-3 inline-flex max-w-full items-start gap-2 rounded-[var(--vpw-radius-md)] border border-[color-mix(in_srgb,var(--vpw-amber)_30%,var(--vpw-bg-card))] bg-[var(--vpw-bg-warning)] px-3 py-2 text-sm text-[color-mix(in_srgb,var(--vpw-amber)_58%,var(--vpw-text-primary))]">
                <ShieldAlert
                  aria-hidden="true"
                  className="mt-0.5 h-4 w-4 shrink-0"
                />
                <span className="leading-5">
                  Revocation is immediate. Rotate automation credentials before
                  deleting project access.
                </span>
              </div>
            ) : null}
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <VpwBadge tone={activeTokens > 0 ? "success" : "neutral"}>
              Active tokens: {activeTokens}
            </VpwBadge>
            <Button onClick={() => setTokenSheetOpen(true)} type="button">
              <Plus aria-hidden="true" className="h-4 w-4" />
              Create token
            </Button>
          </div>
        </div>
        <div className="p-4">
          {apiTokensLoading ? (
            <VpwSkeletonStack rows={6} />
          ) : (
            <VpwDataTable
              caption="API tokens table"
              columns={tokenColumns}
              data={apiTokens}
              density="compact"
              emptyState={
                <VpwEmptyState
                  action={
                    <Button
                      onClick={() => setTokenSheetOpen(true)}
                      type="button"
                      variant="outline"
                    >
                      <Plus aria-hidden="true" className="h-4 w-4" />
                      Create token
                    </Button>
                  }
                  description="Create a token when automation needs scoped access to Workbench APIs."
                  icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
                  title="No API tokens yet"
                />
              }
              getRowKey={(token) => token.id}
              minWidth="920px"
            />
          )}
        </div>
      </VpwPanel>
      <SettingsTokenCreateSheet
        apiTokenActionLoading={apiTokenActionLoading}
        apiTokenName={apiTokenName}
        apiTokenProjectId={apiTokenProjectId}
        apiTokenProjectOptions={apiTokenProjectOptions}
        apiTokenScopeOptions={apiTokenScopeOptions}
        apiTokenScopes={apiTokenScopes}
        createdApiToken={createdApiToken}
        onApiTokenNameChange={onApiTokenNameChange}
        onApiTokenProjectChange={onApiTokenProjectChange}
        onCreateApiToken={onCreateApiToken}
        onOpenChange={handleTokenSheetOpenChange}
        onToggleApiTokenScope={onToggleApiTokenScope}
        open={tokenSheetOpen}
      />
    </VpwSection>
  )
}

type SettingsTokenCreateSheetProps = Pick<
  SettingsApiTokensSectionProps,
  | "apiTokenActionLoading"
  | "apiTokenName"
  | "apiTokenProjectId"
  | "apiTokenProjectOptions"
  | "apiTokenScopeOptions"
  | "apiTokenScopes"
  | "createdApiToken"
  | "onApiTokenNameChange"
  | "onApiTokenProjectChange"
  | "onCreateApiToken"
  | "onToggleApiTokenScope"
> & {
  open: boolean
  onOpenChange: (open: boolean) => void
}

function SettingsTokenCreateSheet({
  apiTokenActionLoading,
  apiTokenName,
  apiTokenProjectId,
  apiTokenProjectOptions,
  apiTokenScopeOptions,
  apiTokenScopes,
  createdApiToken,
  onApiTokenNameChange,
  onApiTokenProjectChange,
  onCreateApiToken,
  onOpenChange,
  onToggleApiTokenScope,
  open,
}: SettingsTokenCreateSheetProps) {
  const tokenHasAdminScope = apiTokenScopes.includes("admin")

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[min(40rem,calc(100vw-2rem))] overflow-y-auto bg-[var(--vpw-bg-card)] p-0 text-[var(--vpw-text-primary)] sm:max-w-[40rem]">
        <SheetHeader className="border-b border-[var(--vpw-border-default)] px-5 py-5 text-left">
          <SheetTitle className="text-xl text-[var(--vpw-text-primary)]">
            Create API token
          </SheetTitle>
          <SheetDescription className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
            Generate a scoped service token for automation. The cleartext secret
            is only available in this drawer after creation.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-6 px-5 py-5">
          <div className="flex flex-col gap-5">
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
                  onChange={(event) =>
                    onApiTokenNameChange(event.target.value)
                  }
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
                {apiTokenActionLoading ? "Creating" : "Create token"}
              </Button>
            </form>
          </div>

          <div className="border-t border-[var(--vpw-border-subtle)] pt-5">
            <VpwSectionHeader
              description="Token secrets are masked by default and only available during the one-time creation response."
              eyebrow="One-time secret"
              title="Creation result"
            />
            <div className="mt-5">
              <SettingsTokenCreationResult createdApiToken={createdApiToken} />
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}
