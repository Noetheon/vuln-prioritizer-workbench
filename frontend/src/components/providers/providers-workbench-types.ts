import type { ProviderStatusPublic } from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"

export type ProvidersWorkbenchProps = {
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  selectedProjectId: string
  onRefreshProviderStatus: () => void
}

export type ProviderSourceRow = {
  cacheAge: string
  detail: string
  id: string
  lastUpdated: string
  name: string
  sourceType: string
  status: string
  tone: VpwBadgeTone
  usedInEvidence: string
  value: string
}

export type ProviderSourceCounts = {
  availableSources: number
  staleSources: number
  missingSources: number
}
