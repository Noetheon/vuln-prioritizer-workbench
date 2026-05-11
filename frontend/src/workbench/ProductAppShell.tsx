import { useNavigate } from "@tanstack/react-router"
import type { ReactNode } from "react"

import {
  LoginService,
  type ProviderStatusPublic,
  type UserPublic,
  type WorkbenchStatus,
} from "../api-client"
import { clearAccessToken } from "../auth"
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
  currentUser: UserPublic | null
  eyebrow: string
  hideStatusStrip?: boolean
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
  title: string
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
    try {
      await LoginService.logoutCurrentToken()
    } catch {
      // Local logout should complete even if the server session already expired.
    } finally {
      clearAccessToken()
      if (typeof window !== "undefined") {
        window.location.assign("/login")
      } else {
        await navigate({ replace: true, search: {} as never, to: "/login" })
      }
    }
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

function currentUserLabel(user: UserPublic | null) {
  return user?.email ?? "Local workspace"
}
