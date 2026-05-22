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
  age: string
  evidenceUse: string
  id: string
  lastUpdated: string
  name: string
  notes: string
  purpose: string
  statusLabel: string
  statusToken: string
  technicalName: string
  tone: VpwBadgeTone
  value: string
}

export type ProviderSourceCounts = {
  availableSources: number
  staleSources: number
  missingSources: number
}
