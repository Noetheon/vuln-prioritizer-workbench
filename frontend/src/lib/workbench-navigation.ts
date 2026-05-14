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
} from "lucide-react"

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

export type NavigationGroup = {
  items: readonly NavigationEntry[]
  label: string
}

export const workbenchNavigationGroups: readonly NavigationGroup[] = [
  {
    label: "Operate",
    items: [
      { label: "Overview", icon: LayoutDashboard, to: "/" },
      { label: "Triage", icon: ListChecks, to: "/findings" },
    ],
  },
  {
    label: "Prepare",
    items: [
      { label: "Imports", icon: FileInput, to: "/imports" },
      { label: "Assets", icon: ShieldCheck, to: "/assets" },
      { label: "Data Sources", icon: Database, to: "/providers" },
    ],
  },
  {
    label: "Govern",
    items: [
      { label: "Risk Acceptance", icon: FileCheck2, to: "/waivers" },
      { label: "Evidence Center", icon: FileArchive, to: "/reports" },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Workspace Settings", icon: Settings, to: "/settings" },
      { label: "Projects", icon: FolderKanban, to: "/projects" },
    ],
  },
]

export const workbenchNavigation: readonly NavigationEntry[] =
  workbenchNavigationGroups.flatMap((group) => group.items)
