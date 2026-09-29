import { Link } from "@/lib/router"
import { LogOut, Sidebar } from "lucide-react"
import type { Dispatch, SetStateAction } from "react"
import { cn } from "../../lib/utils"
import type {
  NavigationGroup,
  WorkbenchPath,
} from "../../lib/workbench-navigation"
import { Button } from "../ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip"

type AppShellSidebarProps = {
  activePath: WorkbenchPath | null
  navigationGroups: readonly NavigationGroup[]
  setSidebarCollapsed: Dispatch<SetStateAction<boolean>>
  sidebarCollapsed: boolean
  signOutUrl?: string | null
  workspaceInitial: string
  workspaceLabel: string
  workspaceStatusLabel?: string
}

export function AppShellSidebar({
  activePath,
  navigationGroups,
  setSidebarCollapsed,
  sidebarCollapsed,
  signOutUrl = null,
  workspaceInitial,
  workspaceLabel,
  workspaceStatusLabel = "Local workspace status",
}: AppShellSidebarProps) {
  return (
    <aside
      aria-label="Workbench sidebar"
      className={cn(
        "hidden h-dvh max-h-dvh shrink-0 flex-col border-r border-[var(--vpw-border-default)] bg-[var(--vpw-bg-page)] transition-[width] duration-200 ease-out lg:flex",
        sidebarCollapsed ? "w-[72px]" : "w-[248px]",
      )}
    >
      <div
        className={cn(
          "flex h-16 shrink-0 items-center border-b border-[var(--vpw-border-default)]",
          sidebarCollapsed ? "justify-center px-0" : "gap-3 px-4",
        )}
      >
        <div
          className={cn(
            "flex shrink-0 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-text-primary)] font-extrabold text-[var(--vpw-bg-card)]",
            sidebarCollapsed ? "size-10 text-sm" : "size-9 text-xs",
          )}
        >
          VP
        </div>
        {!sidebarCollapsed ? (
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
              Vuln Prioritizer
            </p>
            <p className="truncate text-xs text-[var(--vpw-text-muted)]">
              Workbench
            </p>
          </div>
        ) : null}
        {!sidebarCollapsed ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                aria-label="Collapse sidebar"
                aria-pressed={sidebarCollapsed}
                className="ml-auto flex size-9 items-center justify-center rounded-[var(--vpw-radius-md)] text-[var(--vpw-text-muted)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]"
                onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
                size="icon"
                type="button"
                variant="ghost"
              >
                <Sidebar aria-hidden="true" size={16} />
              </Button>
            </TooltipTrigger>
            <TooltipContent align="end" side="bottom" sideOffset={8}>
              Collapse sidebar
            </TooltipContent>
          </Tooltip>
        ) : null}
      </div>

      <nav
        aria-label="Workbench navigation"
        className="min-h-0 flex-1 overflow-y-auto p-2"
      >
        <ul className="flex flex-col gap-1">
          {sidebarCollapsed ? (
            <li>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    aria-label="Expand sidebar"
                    aria-pressed={sidebarCollapsed}
                    className="mx-auto flex size-10 items-center justify-center rounded-[var(--vpw-radius-md)] text-[var(--vpw-text-muted)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]"
                    onClick={() =>
                      setSidebarCollapsed((collapsed) => !collapsed)
                    }
                    size="icon"
                    type="button"
                    variant="ghost"
                  >
                    <Sidebar aria-hidden="true" size={16} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Expand sidebar</TooltipContent>
              </Tooltip>
            </li>
          ) : null}
          {navigationGroups.map((group) => (
            <li key={group.label}>
              {!sidebarCollapsed ? (
                <p className="px-3 pb-1 pt-3 text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
                  {group.label}
                </p>
              ) : null}
              <ul className="flex flex-col gap-1">
                {group.items.map((entry) => {
                  const isActive = activePath === entry.to
                  const navLink = (
                    <Link
                      aria-current={isActive ? "page" : undefined}
                      aria-label={sidebarCollapsed ? entry.label : undefined}
                      className={cn(
                        "flex items-center gap-2.5 rounded-[var(--vpw-radius-md)] text-sm font-medium transition-colors",
                        sidebarCollapsed
                          ? "mx-auto size-10 justify-center p-0"
                          : "min-h-10 w-full px-3",
                        isActive
                          ? "bg-[var(--vpw-text-primary)] text-[var(--vpw-bg-card)]"
                          : "text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
                      )}
                      to={entry.to}
                    >
                      <entry.icon
                        aria-hidden="true"
                        className="shrink-0"
                        size={16}
                      />
                      {!sidebarCollapsed ? (
                        <span className="truncate">{entry.label}</span>
                      ) : null}
                    </Link>
                  )

                  return (
                    <li key={entry.label}>
                      {sidebarCollapsed ? (
                        <Tooltip>
                          <TooltipTrigger asChild>{navLink}</TooltipTrigger>
                          <TooltipContent side="right">
                            {entry.label}
                          </TooltipContent>
                        </Tooltip>
                      ) : (
                        navLink
                      )}
                    </li>
                  )
                })}
              </ul>
            </li>
          ))}
        </ul>
      </nav>

      <div
        className={cn(
          "flex shrink-0 items-center gap-2 border-t border-[var(--vpw-border-default)]",
          sidebarCollapsed ? "flex-col justify-center p-2" : "p-3",
        )}
      >
        <div
          aria-label={workspaceStatusLabel}
          className={cn(
            "flex h-auto min-h-10 items-center justify-start rounded-[var(--vpw-radius-md)] px-2 text-[var(--vpw-text-secondary)]",
            sidebarCollapsed ? "size-10 justify-center p-0" : "w-full",
          )}
          role="status"
        >
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-xs font-semibold text-[var(--vpw-text-secondary)]">
            {workspaceInitial}
          </span>
          {!sidebarCollapsed ? (
            <span className="min-w-0 flex-1 truncate pl-2 text-left text-xs">
              {workspaceLabel}
            </span>
          ) : null}
        </div>
        {signOutUrl ? (
          <SignOutLink compact={sidebarCollapsed} href={signOutUrl} />
        ) : null}
      </div>
    </aside>
  )
}

function SignOutLink({ compact, href }: { compact: boolean; href: string }) {
  const link = (
    <a
      aria-label="Sign out"
      className={cn(
        "flex shrink-0 items-center justify-center gap-2 rounded-[var(--vpw-radius-md)] text-xs text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
        compact ? "size-10" : "min-h-10 px-2",
      )}
      href={href}
    >
      <LogOut aria-hidden="true" size={16} />
      {compact ? null : <span>Sign out</span>}
    </a>
  )
  if (!compact) return link
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">Sign out</TooltipContent>
    </Tooltip>
  )
}
