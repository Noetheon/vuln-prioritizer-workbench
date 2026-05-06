import { useQuery } from "@tanstack/react-query"

import {
  ProvidersService,
  UsersService,
  WorkbenchService,
} from "../api-client"

export const workbenchBootstrapQueryKey = ["workbench", "bootstrap"] as const

export async function loadWorkbenchBootstrap() {
  const [status, providerStatus, currentUser] = await Promise.all([
    WorkbenchService.templateWorkbenchStatus(),
    ProvidersService.readProviderStatus(),
    UsersService.readUserMe(),
  ])
  return { currentUser, providerStatus, status }
}

export function useWorkbenchBootstrapQuery() {
  return useQuery({
    queryFn: loadWorkbenchBootstrap,
    queryKey: workbenchBootstrapQueryKey,
    retry: false,
    staleTime: 30_000,
  })
}
