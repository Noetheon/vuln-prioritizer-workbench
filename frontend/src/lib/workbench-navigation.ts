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
