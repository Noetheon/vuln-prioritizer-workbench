import type { WorkbenchSessionPublic } from "../api-client"

export type ShellIdentity = {
  label: string
  signOutUrl: string | null
  statusLabel: string
}

const localIdentity: ShellIdentity = {
  label: "Local workspace",
  signOutUrl: null,
  statusLabel: "Local workspace status",
}

// Local mode keeps the workspace label; team mode names the user the reverse
// proxy signed in and offers its sign-out URL when one is configured.
export function shellIdentity(
  session: WorkbenchSessionPublic | undefined,
): ShellIdentity {
  if (session?.auth_mode !== "proxy") return localIdentity
  const label = session.display_name.trim() || session.user
  return {
    label,
    signOutUrl: session.logout_url?.trim() || null,
    statusLabel: `Signed in as ${session.user}`,
  }
}
