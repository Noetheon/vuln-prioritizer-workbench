import type {
  ApiTokenCreate,
  ApiTokenPublic,
  ProjectPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  type VpwBadgeTone,
  type VpwDataTableColumn,
} from "@/components/vpw"

export type ApiTokenScope = NonNullable<ApiTokenCreate["scopes"]>[number]

type BuildApiTokenColumnsArgs = {
  actionLoading: boolean
  projects: readonly ProjectPublic[]
  onRevokeApiToken: (token: ApiTokenPublic) => void | Promise<void>
}

export function formatDateTime(value: string | null | undefined) {
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

export function formatScopes(scopes: readonly ApiTokenScope[]) {
  return scopes.length > 0
    ? scopes.map((scope) => scope.toUpperCase()).join(", ")
    : "No scopes"
}

export function activeTokenCount(tokens: readonly ApiTokenPublic[]) {
  return tokens.filter((token) => token.active).length
}

export function tokenActivityPercent(tokens: readonly ApiTokenPublic[]) {
  if (tokens.length === 0) {
    return 0
  }
  return Math.round((activeTokenCount(tokens) / tokens.length) * 100)
}

export function buildApiTokenColumns({
  actionLoading,
  projects,
  onRevokeApiToken,
}: BuildApiTokenColumnsArgs): VpwDataTableColumn<ApiTokenPublic>[] {
  return [
    {
      id: "name",
      header: "Name",
      cell: (token) => (
        <div className="min-w-40">
          <p className="font-medium text-[var(--vpw-text-primary)]">
            {token.name}
          </p>
          <p className="mt-1 truncate font-mono text-xs text-[var(--vpw-text-muted)]">
            {token.id}
          </p>
        </div>
      ),
    },
    {
      id: "scopes",
      header: "Scopes",
      cell: (token) => (
        <div className="flex flex-wrap gap-1.5">
          {token.scopes.map((scope) => (
            <VpwBadge key={scope} tone="support">
              {scope.toUpperCase()}
            </VpwBadge>
          ))}
        </div>
      ),
    },
    {
      id: "project",
      header: "Project",
      cell: (token) => projectScopeLabel(token.project_id, projects),
    },
    {
      id: "created",
      header: "Created",
      cell: (token) => formatDateTime(token.created_at),
      className: "whitespace-nowrap",
    },
    {
      id: "last-used",
      header: "Last used",
      cell: (token) => formatDateTime(token.last_used_at),
      className: "whitespace-nowrap",
    },
    {
      id: "expires",
      header: "Expires",
      cell: (token) => formatDateTime(token.expires_at),
      className: "whitespace-nowrap",
    },
    {
      id: "status",
      header: "Status",
      cell: (token) => (
        <VpwBadge tone={statusBadgeTone(token.active)}>
          {statusLabel(token.active)}
        </VpwBadge>
      ),
    },
    {
      id: "actions",
      header: "Actions",
      cell: (token) =>
        token.active ? (
          <Button
            aria-busy={actionLoading}
            disabled={actionLoading}
            onClick={() => void onRevokeApiToken(token)}
            size="sm"
            type="button"
            variant="outline"
          >
            Revoke
          </Button>
        ) : (
          <span className="text-sm text-[var(--vpw-text-muted)]">N.A.</span>
        ),
    },
  ]
}

function projectScopeLabel(
  projectId: string | null | undefined,
  projects: readonly ProjectPublic[],
) {
  if (!projectId) {
    return "Global"
  }
  return projects.find((project) => project.id === projectId)?.name ?? projectId
}

function statusBadgeTone(active: boolean): VpwBadgeTone {
  return active ? "success" : "neutral"
}

function statusLabel(active: boolean) {
  return active ? "Active" : "Revoked"
}
