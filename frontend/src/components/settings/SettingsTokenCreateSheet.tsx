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
  VpwField,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwStatusBanner,
} from "@/components/vpw"
import { Button } from "@/components/ui/button"
import { SettingsTokenCreationResult } from "./SettingsTokenCreationResult"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsTokenCreateSheetProps = Pick<
  SettingsWorkbenchProps,
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

export function SettingsTokenCreateSheet({
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
                          {scopeDescription(scope)}
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

function scopeDescription(scope: string) {
  if (scope === "read") return "Read workbench findings and evidence metadata."
  if (scope === "import") return "Create import runs and normalize supplied inputs."
  if (scope === "report") return "Generate and download report artifacts."
  return "Root-equivalent global access for trusted operators."
}
