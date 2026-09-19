import "@/styles/finding-detail-decision.css"
import "@/styles/finding-detail-evidence.css"
import "@/styles/finding-detail-ttp-history.css"
import "@/styles/responsive.css"
import { useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { useLocation, useParams } from "@/lib/router"
import { FindingDetailRoute as FindingDetailPanel } from "../../components/finding-detail/FindingDetailRoute"
import {
  findingsSearchToUrlSearch,
  parseFindingsSearch,
} from "../../components/findings/findings-search-state"
import type { FindingDetailTab } from "../../lib/app-defaults"
import { apiErrorMessage } from "../../lib/app-errors"
import { useFindingDetailQuery } from "../useWorkbenchQueries"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  invalidateProjectScopedWorkbenchQueries,
  workbenchQueryKeys,
} from "../workbench-query-keys"

function FindingDetailRouteContainer({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient()
  const location = useLocation()
  const { setSelectedProjectId, providerStatus } = useWorkbenchContext()
  const findingsSearch = parseFindingsSearch(
    activeSearchString(location.searchStr),
  )
  const findingDetailQuery = useFindingDetailQuery(findingId)
  const [findingDetailTab, setFindingDetailTab] =
    useState<FindingDetailTab>("decision")
  const findingDetail = findingDetailQuery.data?.detail ?? null

  useEffect(() => {
    setFindingDetailTab("decision")
  }, [])

  useEffect(() => {
    if (findingDetail?.project_id) {
      setSelectedProjectId(findingDetail.project_id)
    }
  }, [findingDetail?.project_id, setSelectedProjectId])

  function refreshFindingDetail() {
    if (findingDetail?.project_id)
      void invalidateProjectScopedWorkbenchQueries(
        queryClient,
        findingDetail.project_id,
      )
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.findingDetail(findingId),
    })
  }

  return (
    <section className="w-full">
      <FindingDetailPanel
        error={
          findingDetailQuery.isError
            ? apiErrorMessage(
                "Finding detail unavailable",
                findingDetailQuery.error,
              )
            : ""
        }
        explanation={findingDetailQuery.data?.explanation ?? null}
        explanationWarning={findingDetailQuery.data?.explanationWarning ?? ""}
        finding={findingDetail}
        latestProviderSnapshotId={providerStatus?.snapshot.id}
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
  const { findingId } = useParams<{ findingId: string }>()

  return <FindingDetailRouteContainer findingId={findingId} />
}

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}
