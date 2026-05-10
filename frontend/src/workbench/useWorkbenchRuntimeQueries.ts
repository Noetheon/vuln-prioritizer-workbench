import { useQuery } from "@tanstack/react-query"

import {
  ProvidersService,
  UsersService,
  WorkbenchService,
} from "../api-client"
import { workbenchQueryKeys } from "./workbench-query-keys"

export const workbenchCurrentUserQueryKey = workbenchQueryKeys.currentUser()
export const workbenchProviderStatusQueryKey = workbenchQueryKeys.providerStatus()
export const workbenchStatusQueryKey = workbenchQueryKeys.status()

export function useWorkbenchCurrentUserQuery() {
  return useQuery({
    queryFn: () => UsersService.readUserMe(),
    queryKey: workbenchCurrentUserQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}

export function useWorkbenchProviderStatusQuery() {
  return useQuery({
    queryFn: () => ProvidersService.readProviderStatus(),
    queryKey: workbenchProviderStatusQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}

export function useWorkbenchStatusQuery() {
  return useQuery({
    queryFn: () => WorkbenchService.workbenchStatus(),
    queryKey: workbenchStatusQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}
