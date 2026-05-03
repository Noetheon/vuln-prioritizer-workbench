import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
} from "../../api-client"
import {
  formatCacheAge,
  formatProviderFreshness,
  providerDataQualityNotes,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceLabel,
  providerSourceState,
} from "../../lib/provider-format"
import { DataQualityNotice, type DataQualityNoticeItem } from "../states"
import { VpwPanel } from "../vpw"

type ProviderFreshnessPanelProps = {
  providerStatus: ProviderStatusPublic | null
  statusError: string
}

const fallbackProviderSources: ProviderSourceStatusPublic[] = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]

function providerQualityItems(
  providerStatus: ProviderStatusPublic | null,
  statusError: string,
): DataQualityNoticeItem[] {
  return [
    ...providerDataQualityNotes(providerStatus).map((note) => ({
      detail: "Dashboard evidence",
      label: "Provider snapshot",
      message: note,
    })),
    ...(providerStatus?.warnings ?? []).map((warning) => ({
      detail: "Degraded evidence",
      label: "Warning",
      message: warning,
    })),
    ...(providerStatus?.last_error || statusError
      ? [
          {
            detail: "Provider update failure",
            label: "Last Error",
            message: providerStatus?.last_error ?? statusError,
          },
        ]
      : []),
  ]
}

export function ProviderFreshnessPanel({
  providerStatus,
  statusError,
}: ProviderFreshnessPanelProps) {
  const freshness = formatProviderFreshness(providerStatus)
  const qualityItems = providerQualityItems(providerStatus, statusError)

  return (
    <VpwPanel
      className="provider-freshness-panel"
      aria-label="Provider Freshness"
      role="region"
    >
      <div className="dashboard-panel-heading">
        <div>
          <span>Evidence Quality</span>
          <h3>Provider Freshness</h3>
          <p>{providerSnapshotSummary(providerStatus)}</p>
        </div>
        <strong className={`freshness-pill tone-${freshness.tone}`}>
          {freshness.value}
        </strong>
      </div>

      <dl className="freshness-facts">
        <div>
          <dt>Status</dt>
          <dd>{providerStatus?.status ?? "loading"}</dd>
        </div>
        <div>
          <dt>Snapshot</dt>
          <dd>{providerStatus?.snapshot_mode ?? "missing"}</dd>
        </div>
        <div>
          <dt>Last sync</dt>
          <dd>{providerStatus?.last_sync ?? "N.A."}</dd>
        </div>
        <div>
          <dt>Cache age</dt>
          <dd>{formatCacheAge(providerStatus?.cache_age_seconds)}</dd>
        </div>
      </dl>

      <ul
        className="dashboard-provider-sources"
        aria-label="Dashboard provider sources"
      >
        {(providerStatus?.sources ?? fallbackProviderSources).map((source) => (
          <li
            className={`dashboard-provider-source ${providerSourceState(source)}`}
            key={source.name}
            title={providerSourceDetail(source)}
          >
            <strong>{providerSourceLabel(source)}</strong>
            <span>{source.value ?? "N.A."}</span>
          </li>
        ))}
      </ul>

      <DataQualityNotice items={qualityItems} />
    </VpwPanel>
  )
}
