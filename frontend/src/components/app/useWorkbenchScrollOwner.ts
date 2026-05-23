import type { RefObject } from "react"

export function useWorkbenchScrollOwner(
  contentRef: RefObject<HTMLElement | null>,
) {
  // AppShell keeps this ref for route scroll restoration. Native browser
  // scrolling handles wheel, trackpad momentum, and nested scroll handoff.
  void contentRef
  return {}
}
