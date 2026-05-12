import { useLocation, useParams } from "@/lib/router"
import { useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { FindingDetailRoute as FindingDetailPanel } from "../../components/finding-detail/FindingDetailRoute"
import { apiErrorMessage } from "../../lib/app-errors"
import type { FindingDetailTab } from "../../lib/app-defaults"
import {
  findingsSearchToUrlSearch,
  parseFindingsSearch,
} from "../../components/findings/findings-search-state"
import { useWorkbenchContext } from "../WorkbenchContext"
import { useFindingDetailQuery } from "../useWorkbenchQueries"
import { workbenchQueryKeys } from "../workbench-query-keys"

function FindingDetailRouteContainer({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient()
  const location = useLocation()
  const { setSelectedProjectId } = useWorkbenchContext()
  const findingsSearch = parseFindingsSearch(activeSearchString(location.searchStr))
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
    <section className="w-full">
      <FindingDetailPanel
        error={
          findingDetailQuery.isError
            ? apiErrorMessage("Finding detail unavailable", findingDetailQuery.error)
            : ""
        }
        explanation={findingDetailQuery.data?.explanation ?? null}
        explanationWarning={findingDetailQuery.data?.explanationWarning ?? ""}
        finding={findingDetail}
        findingsBackSearch={findingsSearchToUrlSearch(findingsSearch)}
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

  return <FindingDetailRouteContainer findingId={findingId} />
}

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}
