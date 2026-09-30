import { useState } from "react"

/**
 * Runs `reset` in the render where the active project changes, so a page
 * drops drawers, selections, and messages of the previous project before
 * they can show. `reset` may only set state of the calling component.
 */
export function useProjectChangeReset(projectId: string, reset: () => void) {
  const [previousProjectId, setPreviousProjectId] = useState(projectId)
  if (previousProjectId !== projectId) {
    setPreviousProjectId(projectId)
    reset()
  }
}
