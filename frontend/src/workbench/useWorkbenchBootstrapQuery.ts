import { useQuery } from "@tanstack/react-query"

import {
  ProvidersService,
  UsersService,
  WorkbenchService,
} from "../api-client"
import { workbenchQueryKeys } from "./workbench-query-keys"

export const workbenchBootstrapQueryKey = workbenchQueryKeys.bootstrap()

export async function loadWorkbenchBootstrap() {
  const [status, providerStatus, currentUser] = await Promise.all([
    WorkbenchService.workbenchStatus(),
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
