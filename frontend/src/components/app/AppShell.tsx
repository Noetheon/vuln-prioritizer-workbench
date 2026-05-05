import { Link, useNavigate } from "@tanstack/react-router"
import {
  Database,
  FileArchive,
  FileCheck2,
  FileInput,
  FolderKanban,
  LayoutDashboard,
  ListChecks,
  LogOut,
  type LucideIcon,
  Menu,
  Settings,
  ShieldCheck,
  Sidebar,
} from "lucide-react"
import { type ReactNode, useEffect, useState } from "react"
import type {
  ProviderStatusPublic,
  UserPublic,
  WorkbenchStatus,
} from "../../api-client"
import { clearAccessToken } from "../../auth"
import {
  dataServicesSummary,
  workspaceHealthLabel,
} from "../../lib/provider-format"
import { cn } from "../../lib/utils"
import { Button } from "../ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "../ui/sheet"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "../ui/tooltip"

export type WorkbenchPath =
  | "/"
  | "/projects"
  | "/imports"
  | "/findings"
  | "/waivers"
  | "/assets"
  | "/providers"
  | "/reports"
  | "/settings"

export type NavigationEntry = {
  icon: LucideIcon
  label: string
  to: WorkbenchPath
}

export type StatusSummaryItem = {
  label: string
  value: ReactNode
}

type PageHeaderProps = {
  eyebrow: string
  title: string
}

type ProviderHealthIndicatorProps = {
  label: string
}

type AppTopbarProps = PageHeaderProps & {
  healthLabel: string
  onSignOut: () => Promise<void> | void
}

type AppSidebarProps = {
  activePath: WorkbenchPath
  currentUserLabel: string
  navigation: readonly NavigationEntry[]
  onSignOut: () => Promise<void> | void
}

type AppShellProps = AppTopbarProps &
  AppSidebarProps & {
    children: ReactNode
    statusItems: readonly StatusSummaryItem[]
    hideStatusStrip?: boolean
  }

type ProjectSelectorProps = {
  ariaLabel?: string
  disabled?: boolean
  emptyLabel?: string
  label: string
  onChange: (projectId: string) => void
  projects: readonly { id: string; name: string }[]
  value: string
}

type ProductAppShellProps = PageHeaderProps & {
  activePath: WorkbenchPath
  children: ReactNode
  currentUser: UserPublic | null
  hideStatusStrip?: boolean
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}

const sidebarStorageKey = "vpw-sidebar-collapsed"

export const workbenchNavigation: readonly NavigationEntry[] = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
  { label: "Waivers", icon: FileCheck2, to: "/waivers" },
  { label: "Assets", icon: ShieldCheck, to: "/assets" },
  { label: "Providers", icon: Database, to: "/providers" },
  { label: "Reports", icon: FileArchive, to: "/reports" },
  { label: "Settings", icon: Settings, to: "/settings" },
]

export function AppShell({
  activePath,
  children,
  currentUserLabel,
  eyebrow,
  healthLabel,
  hideStatusStrip = false,
  navigation,
  onSignOut,
  statusItems,
  title,
}: AppShellProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false
    return window.localStorage.getItem(sidebarStorageKey) === "true"
  })

  useEffect(() => {
    window.localStorage.setItem(sidebarStorageKey, String(sidebarCollapsed))
  }, [sidebarCollapsed])

  const isHealthy =
    !healthLabel.toLowerCase().includes("unavailable") &&
    !healthLabel.toLowerCase().includes("error") &&
    !healthLabel.toLowerCase().includes("degraded")

  return (
    <TooltipProvider>
      <div className="flex min-h-dvh overflow-x-hidden bg-[var(--vpw-bg-app)] lg:h-screen lg:overflow-hidden">
        {/* ── Sidebar ── */}
        <aside
          aria-label="Workbench sidebar"
          className={cn(
            "relative hidden shrink-0 flex-col border-r border-slate-800/80 bg-[var(--vpw-navy)] transition-[width] duration-200 ease-out lg:flex",
            sidebarCollapsed ? "w-[72px]" : "w-[248px]",
          )}
        >
          {/* Brand */}
          <div
            className={cn(
              "flex h-16 shrink-0 items-center border-b border-slate-800/80",
              sidebarCollapsed ? "justify-center px-0" : "gap-3 px-4",
            )}
          >
            <div
              className={cn(
                "flex shrink-0 items-center justify-center rounded-lg bg-amber-500 font-extrabold text-slate-950",
                sidebarCollapsed ? "size-10 text-sm" : "size-9 text-xs",
              )}
            >
              VP
            </div>
            {!sidebarCollapsed ? (
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-white">
                  Vuln Prioritizer
                </p>
                <p className="truncate text-xs text-slate-500">Workbench</p>
              </div>
            ) : null}
            {!sidebarCollapsed ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    aria-label="Collapse sidebar"
                    aria-pressed={sidebarCollapsed}
                    className="ml-auto flex size-9 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200"
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
                <TooltipContent side="right">Collapse sidebar</TooltipContent>
              </Tooltip>
            ) : null}
          </div>

          {/* Nav */}
          <nav
            aria-label="Workbench navigation"
            className="flex-1 overflow-y-auto p-2"
          >
            <ul className="flex flex-col gap-1">
              {sidebarCollapsed ? (
                <li>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        aria-label="Expand sidebar"
                        aria-pressed={sidebarCollapsed}
                        className="mx-auto flex size-10 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200"
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
              {navigation.map((entry) => {
                const isActive = activePath === entry.to
                const navLink = (
                  <Link
                    aria-current={isActive ? "page" : undefined}
                    aria-label={sidebarCollapsed ? entry.label : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-md text-sm font-medium transition-colors",
                      sidebarCollapsed
                        ? "mx-auto size-10 justify-center p-0"
                        : "min-h-10 w-full px-3",
                      isActive
                        ? "bg-white/10 text-white"
                        : "text-slate-400 hover:bg-white/5 hover:text-slate-200",
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
          </nav>

          {/* Footer */}
          <div
            className={cn(
              "flex shrink-0 items-center gap-2 border-t border-slate-800/80",
              sidebarCollapsed ? "flex-col justify-center p-2" : "p-3",
            )}
          >
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  aria-label="Account menu"
                  className={cn(
                    "h-auto min-h-10 justify-start rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200",
                    sidebarCollapsed
                      ? "size-10 justify-center p-0"
                      : "w-full px-2",
                  )}
                  type="button"
                  variant="ghost"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-300">
                    {currentUserLabel.charAt(0).toUpperCase()}
                  </span>
                  {!sidebarCollapsed ? (
                    <span className="min-w-0 flex-1 truncate text-left text-xs">
                      {currentUserLabel}
                    </span>
                  ) : null}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="start"
                className="w-56"
                side="top"
                sideOffset={8}
              >
                <DropdownMenuLabel>
                  <span className="block text-sm">Account</span>
                  <span className="block truncate text-muted-foreground text-xs font-normal">
                    {currentUserLabel}
                  </span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuGroup>
                  <DropdownMenuItem onSelect={() => void onSignOut()}>
                    <LogOut aria-hidden="true" size={14} />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </aside>

        {/* ── Main area ── */}
        <main className="flex min-h-dvh min-w-0 flex-1 flex-col lg:min-h-0 lg:overflow-hidden">
          {/* Topbar */}
          <header className="flex min-h-14 shrink-0 items-center justify-between gap-3 border-b border-[var(--vpw-border-default)] bg-[var(--vpw-bg-page)] px-4 py-3 lg:h-14 lg:px-6 lg:py-0">
            <div className="flex min-w-0 items-center gap-3">
              <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
                <SheetTrigger asChild>
                  <Button
                    aria-label="Open navigation"
                    className="size-9 border-[var(--vpw-border-default)] text-[var(--vpw-text-secondary)] lg:hidden"
                    size="icon"
                    type="button"
                    variant="outline"
                  >
                    <Menu aria-hidden="true" size={18} />
                  </Button>
                </SheetTrigger>
                <SheetContent
                  className="flex w-[min(22rem,calc(100vw-2rem))] flex-col overflow-y-auto bg-[var(--vpw-navy)] p-0 text-white"
                  side="left"
                >
                  <SheetHeader className="border-b border-slate-800/80 px-4 py-4 text-left">
                    <div className="flex items-center gap-3">
                      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-amber-500 text-xs font-extrabold text-slate-950">
                        VP
                      </div>
                      <div className="min-w-0">
                        <SheetTitle className="truncate text-sm font-semibold text-white">
                          Vuln Prioritizer
                        </SheetTitle>
                        <SheetDescription className="truncate text-xs text-slate-400">
                          Workbench
                        </SheetDescription>
                      </div>
                    </div>
                  </SheetHeader>
                  <nav
                    aria-label="Workbench mobile navigation"
                    className="flex-1 p-2"
                  >
                    <ul className="flex flex-col gap-1">
                      {navigation.map((entry) => {
                        const isActive = activePath === entry.to
                        return (
                          <li key={entry.label}>
                            <Link
                              aria-current={isActive ? "page" : undefined}
                              className={cn(
                                "flex min-h-11 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors",
                                isActive
                                  ? "bg-white/10 text-white"
                                  : "text-slate-300 hover:bg-white/5 hover:text-white",
                              )}
                              onClick={() => setMobileNavOpen(false)}
                              to={entry.to}
                            >
                              <entry.icon
                                aria-hidden="true"
                                className="shrink-0"
                                size={17}
                              />
                              <span className="truncate">{entry.label}</span>
                            </Link>
                          </li>
                        )
                      })}
                    </ul>
                  </nav>
                  <div className="flex shrink-0 items-center gap-2 border-t border-slate-800/80 p-3">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-300">
                      {currentUserLabel.charAt(0).toUpperCase()}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-left text-xs text-slate-300">
                      {currentUserLabel}
                    </span>
                    <Button
                      aria-label="Sign out"
                      className="size-9 shrink-0 text-slate-300 hover:bg-white/5 hover:text-white"
                      onClick={() => void onSignOut()}
                      size="icon"
                      type="button"
                      variant="ghost"
                    >
                      <LogOut aria-hidden="true" size={15} />
                    </Button>
                  </div>
                </SheetContent>
              </Sheet>
              <div className="min-w-0">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                  {eyebrow}
                </p>
                <h1 className="truncate text-base font-bold leading-tight text-slate-900">
                  {title}
                </h1>
              </div>
            </div>
            <div className="flex min-w-0 shrink-0 items-center gap-1.5">
              <div
                className={cn(
                  "size-2 rounded-full",
                  isHealthy ? "bg-green-500" : "bg-amber-500",
                )}
              />
              <span className="max-w-[8.5rem] truncate text-sm text-slate-600 sm:max-w-none">
                {healthLabel}
              </span>
            </div>
          </header>

          {/* Status strip */}
          {!hideStatusStrip && statusItems.length > 0 && (
            <div className="shrink-0 overflow-x-auto border-b border-[var(--vpw-border-subtle)] bg-white/80">
              <div className="flex min-w-max items-stretch lg:min-w-0">
                {statusItems.map((item, index) => (
                  <div
                    className={cn(
                      "flex min-w-36 flex-col justify-center px-4 py-2 lg:min-w-0 lg:px-6",
                      index > 0 && "border-l border-slate-100",
                    )}
                    key={typeof item.label === "string" ? item.label : index}
                  >
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      {item.label}
                    </span>
                    <span className="mt-0.5 truncate text-sm font-semibold text-slate-800">
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scrollable content */}
          <div className="min-w-0 flex-1 lg:overflow-y-auto">
            <div className="vpw-page-container py-6">{children}</div>
          </div>
        </main>
      </div>
    </TooltipProvider>
  )
}

export function ProductAppShell({
  activePath,
  children,
  currentUser,
  eyebrow,
  hideStatusStrip = false,
  providerStatus,
  status,
  statusError,
  title,
}: ProductAppShellProps) {
  const navigate = useNavigate()

  async function signOut() {
    clearAccessToken()
    await navigate({ to: "/login" })
  }

  return (
    <AppShell
      activePath={activePath}
      currentUserLabel={currentUserLabel(currentUser)}
      eyebrow={eyebrow}
      healthLabel={workspaceHealthLabel(status, statusError)}
      hideStatusStrip={hideStatusStrip}
      navigation={workbenchNavigation}
      onSignOut={signOut}
      statusItems={dataServicesSummary(status, providerStatus)}
      title={title}
    >
      {children}
    </AppShell>
  )
}

export function AppSidebar({
  activePath,
  currentUserLabel,
  navigation,
  onSignOut,
}: AppSidebarProps) {
  const isActive = (path: WorkbenchPath) => activePath === path

  return (
    <aside
      aria-label="Workbench sidebar"
      className="flex w-62 shrink-0 flex-col bg-slate-950 border-r border-slate-800/80"
    >
      <div className="flex h-14 shrink-0 items-center gap-3 border-b border-slate-800/80 px-4">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-amber-500 text-xs font-extrabold text-slate-950">
          VP
        </div>
        <div>
          <p className="text-sm font-semibold text-white">Vuln Prioritizer</p>
          <p className="text-xs text-slate-500">Workbench</p>
        </div>
      </div>
      <nav aria-label="Workbench navigation" className="flex-1 p-2">
        <ul className="space-y-0.5">
          {navigation.map((entry) => (
            <li key={entry.label}>
              <Link
                aria-current={isActive(entry.to) ? "page" : undefined}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive(entry.to)
                    ? "bg-white/10 text-white"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-200",
                )}
                to={entry.to}
              >
                <entry.icon aria-hidden="true" size={16} />
                {entry.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <div className="shrink-0 flex items-center gap-2 border-t border-slate-800/80 p-3">
        <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-300">
          {currentUserLabel.charAt(0).toUpperCase()}
        </div>
        <span className="flex-1 truncate text-xs text-slate-400">
          {currentUserLabel}
        </span>
        <Button
          aria-label="Sign out"
          className="size-7 shrink-0 text-slate-500 hover:bg-white/5 hover:text-slate-300"
          onClick={onSignOut}
          size="icon"
          type="button"
          variant="ghost"
        >
          <LogOut aria-hidden="true" size={14} />
        </Button>
      </div>
    </aside>
  )
}

export function AppTopbar({
  eyebrow,
  healthLabel,
  onSignOut,
  title,
}: AppTopbarProps) {
  const isHealthy =
    !healthLabel.toLowerCase().includes("unavailable") &&
    !healthLabel.toLowerCase().includes("error") &&
    !healthLabel.toLowerCase().includes("degraded")

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-6">
      <div>
        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
          {eyebrow}
        </p>
        <h1 className="text-base font-bold leading-tight text-slate-900">
          {title}
        </h1>
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <div
            className={cn(
              "size-2 rounded-full",
              isHealthy ? "bg-green-500" : "bg-amber-500",
            )}
          />
          <span className="text-sm text-slate-600">{healthLabel}</span>
        </div>
        <Button
          aria-label="Sign out"
          className="size-8 border-slate-200 text-slate-400 hover:bg-slate-50 hover:text-slate-700"
          onClick={onSignOut}
          size="icon"
          type="button"
          variant="outline"
        >
          <LogOut aria-hidden="true" size={15} />
        </Button>
      </div>
    </header>
  )
}

export function PageHeader({ eyebrow, title }: PageHeaderProps) {
  return (
    <div>
      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
        {eyebrow}
      </p>
      <h1 className="text-base font-bold leading-tight text-slate-900">
        {title}
      </h1>
    </div>
  )
}

export function ProviderHealthIndicator({
  label,
}: ProviderHealthIndicatorProps) {
  const isHealthy =
    !label.toLowerCase().includes("unavailable") &&
    !label.toLowerCase().includes("error")
  return (
    <div
      aria-label="Workspace health"
      className="flex items-center gap-1.5"
      role="status"
    >
      <div
        className={cn(
          "size-2 rounded-full",
          isHealthy ? "bg-green-500" : "bg-amber-500",
        )}
      />
      <span className="text-sm text-slate-600">{label}</span>
    </div>
  )
}

export function StatusSummary({
  items,
}: {
  items: readonly StatusSummaryItem[]
}) {
  if (items.length === 0) return null
  return (
    <section
      aria-label="Data services summary"
      className="flex shrink-0 items-stretch border-b border-slate-100 bg-white/80"
    >
      {items.map((item, index) => (
        <div
          className={cn(
            "flex flex-col justify-center px-6 py-2",
            index > 0 && "border-l border-slate-100",
          )}
          key={typeof item.label === "string" ? item.label : index}
        >
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
            {item.label}
          </span>
          <span className="mt-0.5 text-sm font-semibold text-slate-800">
            {item.value}
          </span>
        </div>
      ))}
    </section>
  )
}

export function ProjectSelector({
  ariaLabel,
  disabled = false,
  emptyLabel = "No projects",
  label,
  onChange,
  projects,
  value,
}: ProjectSelectorProps) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <Select
        disabled={disabled || projects.length === 0}
        onValueChange={onChange}
        value={value}
      >
        <SelectTrigger
          aria-label={ariaLabel ?? label}
          className="h-8 w-44 text-xs"
        >
          <SelectValue placeholder={emptyLabel} />
        </SelectTrigger>
        <SelectContent>
          {projects.map((project) => (
            <SelectItem key={project.id} value={project.id}>
              {project.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function currentUserLabel(user: UserPublic | null) {
  return user?.email ?? "Local workspace"
}
