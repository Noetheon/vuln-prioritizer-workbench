import type { ReactNode } from "react"

import type {
  ProviderStatusPublic,
  WorkbenchStatus,
} from "../api-client"
import { AppShell } from "../components/app/AppShell"
import {
  dataServicesSummary,
  workspaceHealthLabel,
} from "../lib/provider-format"
import {
  type WorkbenchPath,
  workbenchNavigation,
} from "../lib/workbench-navigation"

type ProductAppShellProps = {
  activePath: WorkbenchPath | null
  children: ReactNode
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
  eyebrow,
  hideStatusStrip = false,
  navigationKey,
  providerStatus,
  status,
  statusError,
  title,
}: ProductAppShellProps) {
  return (
    <AppShell
      activePath={activePath}
      eyebrow={eyebrow}
      healthLabel={workspaceHealthLabel(status, statusError)}
      hideStatusStrip={hideStatusStrip}
      navigation={workbenchNavigation}
      navigationKey={navigationKey}
      statusItems={dataServicesSummary(status, providerStatus)}
      title={title}
      workspaceLabel="Local workspace"
    >
      {children}
    </AppShell>
  )
}
