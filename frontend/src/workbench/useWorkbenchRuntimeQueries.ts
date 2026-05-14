import { useQuery } from "@tanstack/react-query"

import { ProvidersService, WorkbenchService } from "../api-client"
import { workbenchQueryKeys } from "./workbench-query-keys"

export const workbenchProviderStatusQueryKey = workbenchQueryKeys.providerStatus()
export const workbenchStatusQueryKey = workbenchQueryKeys.status()
export const workbenchDemoWorkspaceQueryKey = workbenchQueryKeys.demoWorkspace()

export function useWorkbenchProviderStatusQuery() {
  return useQuery({
    queryFn: ({ signal }) => ProvidersService.readProviderStatus({ signal }),
    queryKey: workbenchProviderStatusQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}

export function useWorkbenchStatusQuery() {
  return useQuery({
    queryFn: ({ signal }) => WorkbenchService.workbenchStatus({ signal }),
    queryKey: workbenchStatusQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}

export function useWorkbenchDemoWorkspaceQuery() {
  return useQuery({
    queryFn: ({ signal }) => WorkbenchService.readDemoWorkspace({ signal }),
    queryKey: workbenchDemoWorkspaceQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}
