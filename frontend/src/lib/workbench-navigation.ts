import {
  Database,
  FileArchive,
  FileCheck2,
  FileInput,
  FolderKanban,
  LayoutDashboard,
  ListChecks,
  type LucideIcon,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react"

export type WorkbenchPath =
  | "/"
  | "/projects"
  | "/imports"
  | "/assets"
  | "/triage"
  | "/risk-acceptance"
  | "/policy"
  | "/evidence"
  | "/data-sources"
  | "/settings"

export type NavigationEntry = {
  icon: LucideIcon
  label: string
  to: WorkbenchPath
}

export type NavigationGroup = {
  items: readonly NavigationEntry[]
  label: string
}

// In the order of the work: set up, triage, govern, report, then the system.
export const workbenchNavigationGroups: readonly NavigationGroup[] = [
  {
    label: "Start",
    items: [{ label: "Overview", icon: LayoutDashboard, to: "/" }],
  },
  {
    label: "Prepare",
    items: [
      { label: "Projects", icon: FolderKanban, to: "/projects" },
      { label: "Imports", icon: FileInput, to: "/imports" },
      { label: "Assets", icon: ShieldCheck, to: "/assets" },
    ],
  },
  {
    label: "Operate",
    items: [{ label: "Triage", icon: ListChecks, to: "/triage" }],
  },
  {
    label: "Govern",
    items: [
      { label: "Risk Acceptance", icon: FileCheck2, to: "/risk-acceptance" },
      { label: "Priority Policy", icon: SlidersHorizontal, to: "/policy" },
    ],
  },
  {
    label: "Report",
    items: [{ label: "Evidence Center", icon: FileArchive, to: "/evidence" }],
  },
  {
    label: "System",
    items: [
      { label: "Data Sources", icon: Database, to: "/data-sources" },
      { label: "Workspace Settings", icon: Settings, to: "/settings" },
    ],
  },
]

export const workbenchNavigation: readonly NavigationEntry[] =
  workbenchNavigationGroups.flatMap((group) => group.items)
