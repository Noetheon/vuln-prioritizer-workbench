import type { ReactNode } from "react"

import type { ProviderStatusPublic, WorkbenchStatus } from "../api-client"
import { AppShell } from "../components/app/AppShell"
import {
  dataServicesSummary,
  workspaceHealthLabel,
} from "../lib/provider-format"
import {
  type WorkbenchPath,
  workbenchNavigationGroups,
} from "../lib/workbench-navigation"
import { shellIdentity } from "../lib/workbench-session"
import { useWorkbenchSessionQuery } from "./useWorkbenchRuntimeQueries"

type ProductAppShellProps = {
  activePath: WorkbenchPath | null
  children: ReactNode
  description: string
  eyebrow: string
  hideStatusStrip?: boolean
  navigationKey: string
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
  title: string
}

export function ProductAppShell({
  activePath,
  children,
  description,
  eyebrow,
  hideStatusStrip = false,
  navigationKey,
  providerStatus,
  status,
  statusError,
  title,
}: ProductAppShellProps) {
  const identity = shellIdentity(useWorkbenchSessionQuery().data)
  return (
    <AppShell
      activePath={activePath}
      description={description}
      eyebrow={eyebrow}
      healthLabel={workspaceHealthLabel(status, statusError)}
      hideStatusStrip={hideStatusStrip}
      navigationGroups={workbenchNavigationGroups}
      navigationKey={navigationKey}
      statusItems={dataServicesSummary(status, providerStatus)}
      title={title}
      signOutUrl={identity.signOutUrl}
      workspaceLabel={identity.label}
      workspaceStatusLabel={identity.statusLabel}
    >
      {children}
    </AppShell>
  )
}
