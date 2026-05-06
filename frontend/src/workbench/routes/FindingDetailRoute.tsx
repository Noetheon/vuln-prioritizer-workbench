import { useParams } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { FindingDetailRoute as FindingDetailPanel } from "../../components/finding-detail/FindingDetailRoute"
import { apiErrorMessage } from "../../lib/app-errors"
import type { FindingDetailTab } from "../../lib/app-defaults"
import { WorkbenchShell } from "../WorkbenchShell"
import { useWorkbenchContext } from "../WorkbenchContext"
import { useFindingDetailQuery } from "../useWorkbenchQueries"
import { workbenchQueryKeys } from "../workbench-query-keys"

function FindingDetailRouteContainer({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient()
  const { setSelectedProjectId } = useWorkbenchContext()
  const findingDetailQuery = useFindingDetailQuery(findingId)
  const [findingDetailTab, setFindingDetailTab] =
    useState<FindingDetailTab>("evidence")
  const findingDetail = findingDetailQuery.data?.detail ?? null

  useEffect(() => {
    setFindingDetailTab("evidence")
  }, [])

  useEffect(() => {
    if (findingDetail?.project_id) {
      setSelectedProjectId(findingDetail.project_id)
    }
  }, [findingDetail?.project_id, setSelectedProjectId])

  function refreshFindingDetail() {
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.findingDetail(findingId),
    })
  }

  return (
    <section className="mx-auto w-full max-w-[2040px] px-4 py-6 sm:px-6 lg:px-8 xl:px-10 2xl:px-12">
      <FindingDetailPanel
        error={
          findingDetailQuery.isError
            ? apiErrorMessage("Finding detail unavailable", findingDetailQuery.error)
            : ""
        }
        explanation={findingDetailQuery.data?.explanation ?? null}
        explanationWarning={findingDetailQuery.data?.explanationWarning ?? ""}
        finding={findingDetail}
        loading={findingDetailQuery.isLoading || findingDetailQuery.isFetching}
        onRefresh={refreshFindingDetail}
        onTabChange={setFindingDetailTab}
        tab={findingDetailTab}
      />
    </section>
  )
}

export function FindingDetailRoute() {
  const { findingId } = useParams({ from: "/_layout/findings/$findingId" })

  return (
    <WorkbenchShell routePath="/findings">
      <FindingDetailRouteContainer findingId={findingId} />
    </WorkbenchShell>
  )
}
