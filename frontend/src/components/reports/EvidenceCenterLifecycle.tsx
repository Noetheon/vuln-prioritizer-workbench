import {
  VpwStatusBanner,
} from "@/components/vpw"
import { statusBannerTone } from "./evidence-center-model"
export { ArtifactSection } from "./EvidenceArtifactSection"
export { EvidenceLifecycle } from "./EvidenceLifecycleFlow"

export function ActionStatus({
  error,
  message,
}: {
  error: string
  message: string
}) {
  if (!error && !message) return null

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <VpwStatusBanner title="Report action failed" tone="critical">
          {error}
        </VpwStatusBanner>
      ) : null}
      {message ? (
        <VpwStatusBanner
          title="Report action complete"
          tone={statusBannerTone(message)}
        >
          {message}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}
