import { useParams } from "@tanstack/react-router"

import { WorkbenchShell } from "../WorkbenchShell"

export function FindingDetailRoute() {
  const { findingId } = useParams({ from: "/_layout/findings/$findingId" })

  return <WorkbenchShell findingDetailId={findingId} routePath="/findings" />
}
