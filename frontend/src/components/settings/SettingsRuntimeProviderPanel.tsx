import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwBadge,
  VpwStatusBanner,
  VpwTableCard,
} from "@/components/vpw"
import {
  providerConfigRows,
} from "./settings-workbench-model"
import {
  ShieldAlert,
  Gauge,
  Zap,
  Camera,
  Clock,
  Upload,
} from "lucide-react"

export function SettingsRuntimeProviderPanel({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  const rows = providerConfigRows(providerStatus)
  const nvd = rows.find((r) => r.id === "nvd")
  const epss = rows.find((r) => r.id === "epss")
  const kev = rows.find((r) => r.id === "kev")
  const snapshotMode = rows.find((r) => r.id === "snapshot-mode")
  const cacheAge = rows.find((r) => r.id === "cache-age")
  const uploadSize = rows.find((r) => r.id === "upload-size")

  return (
    <VpwTableCard
      description="Safe provider configuration values and local execution parameters reported by existing APIs."
      title="Runtime & providers"
    >
      <div className="flex flex-col gap-6 w-full">
        {/* Section 1: Security Data Sources */}
        <div>
          <h3 className="mb-4 font-semibold text-xs text-[var(--vpw-text-muted)] uppercase">
            Security Data Feeds
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* NVD Card */}
            {nvd && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[color-mix(in_srgb,var(--vpw-red)_10%,transparent)] text-[var(--vpw-red)] group-hover:bg-[color-mix(in_srgb,var(--vpw-red)_15%,transparent)] transition-all">
                      <ShieldAlert className="size-5" />
                    </div>
                    <VpwBadge tone={nvd.tone}>{nvd.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {nvd.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {nvd.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Source Type</span>
                  <span className="font-mono text-[var(--vpw-text-primary)] text-[10px]">National Vulnerability DB</span>
                </div>
              </div>
            )}

            {/* EPSS Card */}
            {epss && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[color-mix(in_srgb,var(--vpw-blue)_10%,transparent)] text-[var(--vpw-blue)] group-hover:bg-[color-mix(in_srgb,var(--vpw-blue)_15%,transparent)] transition-all">
                      <Gauge className="size-5" />
                    </div>
                    <VpwBadge tone={epss.tone}>{epss.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {epss.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {epss.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Source Type</span>
                  <span className="font-mono text-[10px] text-[var(--vpw-text-primary)]">EPSS probability signal</span>
                </div>
              </div>
            )}

            {/* KEV Card */}
            {kev && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[color-mix(in_srgb,var(--vpw-amber)_10%,transparent)] text-[var(--vpw-amber)] group-hover:bg-[color-mix(in_srgb,var(--vpw-amber)_15%,transparent)] transition-all">
                      <Zap className="size-5" />
                    </div>
                    <VpwBadge tone={kev.tone}>{kev.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {kev.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {kev.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Source Type</span>
                  <span className="font-mono text-[10px] text-[var(--vpw-text-primary)]">CISA KEV catalog</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Section 2: Engine Parameters */}
        <div className="border-t border-[var(--vpw-border-subtle)] pt-6">
          <h3 className="mb-4 font-semibold text-xs text-[var(--vpw-text-muted)] uppercase">
            Engine & Caching Parameters
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Snapshot Mode Card */}
            {snapshotMode && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[color-mix(in_srgb,var(--vpw-teal)_10%,transparent)] text-[var(--vpw-teal)] group-hover:bg-[color-mix(in_srgb,var(--vpw-teal)_15%,transparent)] transition-all">
                      <Camera className="size-5" />
                    </div>
                    <VpwBadge tone={snapshotMode.tone}>{snapshotMode.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {snapshotMode.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {snapshotMode.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Snapshot Strategy</span>
                  <span className="font-mono text-[var(--vpw-text-primary)] text-[10px]">Immutable Cache</span>
                </div>
              </div>
            )}

            {/* Cache Age Card */}
            {cacheAge && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[color-mix(in_srgb,var(--vpw-violet)_10%,transparent)] text-[var(--vpw-violet)] group-hover:bg-[color-mix(in_srgb,var(--vpw-violet)_15%,transparent)] transition-all">
                      <Clock className="size-5" />
                    </div>
                    <VpwBadge tone={cacheAge.tone}>{cacheAge.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {cacheAge.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {cacheAge.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Invalidation Policy</span>
                  <span className="font-mono text-[var(--vpw-text-primary)] text-[10px]">24h Stale Timeout</span>
                </div>
              </div>
            )}

            {/* Upload Size Card */}
            {uploadSize && (
              <div className="settings-card-glow rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5 flex flex-col justify-between group">
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-lg bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-muted)] group-hover:bg-[color-mix(in_srgb,var(--vpw-text-muted)_10%,transparent)] transition-all">
                      <Upload className="size-5" />
                    </div>
                    <VpwBadge tone={uploadSize.tone}>{uploadSize.value}</VpwBadge>
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-[var(--vpw-text-primary)]">
                      {uploadSize.setting}
                    </h4>
                    <p className="text-xs text-[var(--vpw-text-secondary)] mt-2 leading-relaxed">
                      {uploadSize.detail}
                    </p>
                  </div>
                </div>
                <div className="border-t border-[var(--vpw-border-subtle)] mt-4 pt-3 flex items-center justify-between text-xs text-[var(--vpw-text-muted)] font-medium">
                  <span>Server Limits</span>
                  <span className="font-mono text-[var(--vpw-text-primary)] text-[10px]">Standard Gateway</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <VpwStatusBanner title="Secrets are not displayed" tone="info" className="mt-6">
        Provider keys, environment secrets, and stored credentials stay outside
        Settings.
      </VpwStatusBanner>
    </VpwTableCard>
  )
}
